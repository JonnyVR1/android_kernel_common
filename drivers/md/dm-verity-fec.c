/*
 * Copyright (C) 2015 Google, Inc.
 *
 * Author: Sami Tolvanen <samitolvanen@google.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#include "dm-verity-fec.h"

#define DM_MSG_PREFIX	"verity-fec"

/*
 * If error correction has been configured, returns true.
 */
bool verity_fec_is_enabled(struct dm_verity *v)
{
	return v->fec && v->fec->dev;
}

/*
 * Return a pointer to dm_verity_fec_io after dm_verity_io and its variable
 * length fields.
 */
static inline struct dm_verity_fec_io *fec_io(struct dm_verity_io *io)
{
	return (struct dm_verity_fec_io *) verity_io_digest_end(io->v, io);
}

/*
 * Return an interleaved offset for a byte in RS block.
 */
static inline u64 fec_interleave(struct dm_verity *v, u64 offset)
{
	u32 mod;

	mod = do_div(offset, v->fec->rsn);
	return offset + mod * (v->fec->rounds << v->data_dev_block_bits);
}

/*
 * Decode an RS block using Reed-Solomon.
 */
static int fec_decode_rs8(struct dm_verity *v, struct dm_verity_fec_io *fio,
			  u8 *data, u8 *fec, int neras)
{
	int i;
	uint16_t par[DM_VERITY_FEC_RSM - DM_VERITY_FEC_MIN_RSN];

	for (i = 0; i < v->fec->roots; i++)
		par[i] = fec[i];

	return decode_rs8(fio->rs, data, par, v->fec->rsn, NULL, neras,
			  fio->erasures, 0, NULL);
}

/*
 * Read error-correcting codes for the requested RS block. Returns a pointer
 * to the data block. Caller is responsible for releasing buf.
 */
static u8 *fec_read_parity(struct dm_verity *v, u64 rsb, int index,
			   unsigned *offset, struct dm_buffer **buf)
{
	u64 position, block;
	u8 *res;

	position = (index + rsb) * v->fec->roots;
	block = position >> v->data_dev_block_bits;

	*offset = (unsigned)(position - (block << v->data_dev_block_bits));

	res = dm_bufio_read(v->fec->bufio, v->fec->start + block, buf);

	if (unlikely(IS_ERR(res))) {
		DMERR("%s: FEC %llu: parity read failed (block %llu): %ld",
		      v->data_dev->name, (unsigned long long)rsb,
		      (unsigned long long)(v->fec->start + block),
		      PTR_ERR(res));
		*buf = NULL;
		return NULL;
	}

	return res;
}

/* Loop over each preallocated buffer slot. */
#define fec_for_each_prealloc_buffer(__i) \
	for (__i = 0; __i < DM_VERITY_FEC_BUF_PREALLOC; __i++)

/* Loop over each extra buffer slot. */
#define fec_for_each_extra_buffer(io, __i) \
	for (__i = DM_VERITY_FEC_BUF_PREALLOC; __i < DM_VERITY_FEC_BUF_MAX; \
		__i++)

/* Loop over each allocated buffer. */
#define fec_for_each_buffer(io, __i) \
	for (__i = 0; __i < (io)->nbufs; __i++)

/* Loop over each RS block in each allocated buffer. */
#define fec_for_each_buffer_rs_block(io, __i, __j) \
	fec_for_each_buffer(io, __i) \
		for (__j = 0; __j < 1 << DM_VERITY_FEC_BUF_RS_BITS; __j++)

/*
 * Return a pointer to the current RS block when called inside
 * fec_for_each_buffer_rs_block.
 */
static inline u8 *fec_buffer_rs_block(struct dm_verity *v,
				      struct dm_verity_fec_io *fio,
				      unsigned i, unsigned j)
{
	return &fio->bufs[i][j * v->fec->rsn];
}

/*
 * Return an index to the current RS block when called inside
 * fec_for_each_buffer_rs_block.
 */
static inline unsigned fec_buffer_rs_index(unsigned i, unsigned j)
{
	return (i << DM_VERITY_FEC_BUF_RS_BITS) + j;
}

/*
 * Decode all RS blocks from buffers and copy corrected bytes into fio->output
 * starting from block_offset.
 */
static int fec_decode_bufs(struct dm_verity *v, struct dm_verity_fec_io *fio,
			   u64 rsb, int byte_index, unsigned block_offset,
			   int neras)
{
	int r = -1, corrected = 0, res;
	struct dm_buffer *buf;
	unsigned n, i, offset;
	u8 *par, *block;

	par = fec_read_parity(v, rsb, block_offset, &offset, &buf);
	if (unlikely(!par))
		return r;

	/*
	 * Decode the RS blocks we have in bufs. Each RS block results in
	 * one corrected target byte and consumes fec->roots parity bytes.
	 */
	fec_for_each_buffer_rs_block(fio, n, i) {
		block = fec_buffer_rs_block(v, fio, n, i);
		res = fec_decode_rs8(v, fio, block, &par[offset], neras);

		if (res < 0)
			goto error;

		corrected += res;
		fio->output[block_offset] = block[byte_index];

		block_offset++;
		if (block_offset >= 1 << v->data_dev_block_bits)
			goto done;

		/* read the next block when we run out of parity bytes */
		offset += v->fec->roots;
		if (offset >= 1 << v->data_dev_block_bits) {
			dm_bufio_release(buf);

			par = fec_read_parity(v, rsb, block_offset, &offset,
					      &buf);
			if (unlikely(!par))
				return r;
		}
	}

done:
	r = corrected;
error:
	dm_bufio_release(buf);

	if (r < 0 && neras)
		DMERR_LIMIT("%s: FEC %llu: failed to correct: %d",
			    v->data_dev->name, (unsigned long long)rsb, r);
	else if (r > 0)
		DMWARN_LIMIT("%s: FEC %llu: corrected %d errors",
			     v->data_dev->name, (unsigned long long)rsb,
			     r);

	return r;
}

/*
 * Locate data block erasures using verity hashes.
 */
static int fec_is_erasure(struct dm_verity *v, struct dm_verity_io *io,
			  u8 *want_digest, u8 *data)
{
	if (unlikely(verity_hash(v, verity_io_hash_desc(v, io),
				 data, 1 << v->data_dev_block_bits,
				 verity_io_real_digest(v, io))))
		return 0;

	return memcmp(verity_io_real_digest(v, io), want_digest,
		      v->digest_size) != 0;
}

/*
 * Read data blocks that are part of the RS block and deinterleave as much as
 * fits into buffers. Check for erasure locations if neras is non-NULL.
 */
static int fec_read_bufs(struct dm_verity *v, struct dm_verity_io *io,
			 u64 rsb, u64 target, unsigned block_offset,
			 int *neras)
{
	int i, j, target_index = -1;
	struct dm_buffer *buf;
	struct dm_bufio_client *bufio;
	struct dm_verity_fec_io *fio = fec_io(io);
	u64 block, ileaved;
	u8 *bbuf, *rs_block;
	u8 want_digest[v->digest_size];
	unsigned n, k;

	if (neras)
		*neras = 0;

	/*
	 * read each of the rsn data blocks that are part of the RS block, and
	 * interleave contents to available bufs
	 */
	for (i = 0; i < v->fec->rsn; i++) {
		ileaved = fec_interleave(v, rsb * v->fec->rsn + i);

		/*
		 * target is the data block we want to correct, target_index is
		 * the index of this block within the rsn RS blocks
		 */
		if (ileaved == target)
			target_index = i;

		block = ileaved >> v->data_dev_block_bits;
		bufio = v->fec->data_bufio;

		if (block >= v->data_blocks) {
			block -= v->data_blocks;

			/*
			 * blocks outside the area were assumed to contain
			 * zeros when encoding data was generated
			 */
			if (unlikely(block >= v->fec->hash_blocks))
				continue;

			block += v->hash_start;
			bufio = v->bufio;
		}

		bbuf = dm_bufio_read(bufio, block, &buf);

		if (unlikely(IS_ERR(bbuf))) {
			DMWARN_LIMIT("%s: FEC %llu: read failed (block %llu): "
				     "%ld (erasures %d)", v->data_dev->name,
				     (unsigned long long)rsb,
				     (unsigned long long)block, PTR_ERR(bbuf),
				     neras ? 0 : 1);

			/* assume the block is corrupted */
			if (neras && *neras <= v->fec->roots)
				fio->erasures[(*neras)++] = i;

			continue;
		}

		/* locate erasures if the block is on the data device */
		if (bufio == v->fec->data_bufio &&
		    verity_hash_for_block(v, io, block, want_digest) == 0) {
			/*
			 * skip if we have already found the theoretical
			 * maximum number (i.e. fec->roots) of erasures
			 */
			if (neras && *neras <= v->fec->roots &&
			    fec_is_erasure(v, io, want_digest, bbuf))
				fio->erasures[(*neras)++] = i;
		}

		/*
		 * deinterleave and copy the bytes that fit into bufs,
		 * starting from block_offset
		 */
		fec_for_each_buffer_rs_block(fio, n, j) {
			k = fec_buffer_rs_index(n, j) + block_offset;

			if (k >= 1 << v->data_dev_block_bits)
				goto done;

			rs_block = fec_buffer_rs_block(v, fio, n, j);
			rs_block[i] = bbuf[k];
		}

done:
		dm_bufio_release(buf);
	}

	return target_index;
}

/*
 * Allocate RS control structure and FEC buffers from preallocated mempools,
 * and attempt to allocate as many extra buffers as available.
 */
static int fec_alloc_bufs(struct dm_verity *v, struct dm_verity_fec_io *fio)
{
	unsigned n;

	if (!fio->rs) {
		fio->rs = mempool_alloc(v->fec->rs_pool, 0);

		if (unlikely(!fio->rs)) {
			DMERR("failed to allocate RS");
			return -ENOMEM;
		}
	}

	fec_for_each_prealloc_buffer(n) {
		if (fio->bufs[n])
			continue;

		fio->bufs[n] = mempool_alloc(v->fec->prealloc_pool, GFP_NOIO);

		if (unlikely(!fio->bufs[n])) {
			DMERR("failed to allocate FEC buffer");
			return -ENOMEM;
		}
	}

	/* try to allocate the maximum number of buffers */
	fec_for_each_extra_buffer(fio, n) {
		if (fio->bufs[n])
			continue;

		fio->bufs[n] = mempool_alloc(v->fec->extra_pool, GFP_NOIO);

		/* we can manage with even one buffer if necessary */
		if (unlikely(!fio->bufs[n]))
			break;
	}

	fio->nbufs = n;

	if (!fio->output) {
		fio->output = mempool_alloc(v->fec->output_pool, GFP_NOIO);

		if (!fio->output) {
			DMERR("failed to allocate FEC page");
			return -ENOMEM;
		}
	}

	return 0;
}

/*
 * Initialize buffers and clear erasures. fec_read_bufs assumes buffers are
 * zeroed before deinterleaving.
 */
static void fec_init_bufs(struct dm_verity *v, struct dm_verity_fec_io *fio)
{
	unsigned n;

	fec_for_each_buffer(fio, n)
		memset(fio->bufs[n], 0,
		       v->fec->rsn << DM_VERITY_FEC_BUF_RS_BITS);

	memset(fio->erasures, 0, sizeof(fio->erasures));
}

/*
 * Decode all RS blocks in a single data block and return the target block
 * (indicated by "offset") in fio->output. If use_erasures is non-zero, uses
 * hashes to locate erasures.
 */
static int fec_decode_rsb(struct dm_verity *v, struct dm_verity_io *io,
			  struct dm_verity_fec_io *fio, u64 rsb, u64 offset,
			  int use_erasures)
{
	int r, neras = 0;
	unsigned pos;

	r = fec_alloc_bufs(v, fio);
	if (unlikely(r < 0))
		return -1;

	for (pos = 0; pos < 1 << v->data_dev_block_bits; ) {
		fec_init_bufs(v, fio);

		r = fec_read_bufs(v, io, rsb, offset, pos,
				  use_erasures ? &neras : NULL);
		if (unlikely(r < 0))
			return r;

		r = fec_decode_bufs(v, fio, rsb, r, pos, neras);
		if (r < 0)
			return r;

		pos += fio->nbufs << DM_VERITY_FEC_BUF_RS_BITS;
	}

	/* Always re-validate the corrected block against the expected hash */
	r = verity_hash(v, verity_io_hash_desc(v, io), fio->output,
			1 << v->data_dev_block_bits,
			verity_io_real_digest(v, io));
	if (unlikely(r < 0))
		return r;

	if (memcmp(verity_io_real_digest(v, io), verity_io_want_digest(v, io),
		   v->digest_size)) {
		DMERR_LIMIT("%s: FEC %llu: failed to correct (%d erasures)",
			    v->data_dev->name, (unsigned long long)rsb,
			    neras);
		return -1;
	}

	return 0;
}

static int fec_bv_copy(struct dm_verity *v, struct dm_verity_io *io, u8 *data,
		       size_t len)
{
	struct dm_verity_fec_io *fio = fec_io(io);

	memcpy(data, &fio->output[fio->output_pos], len);
	fio->output_pos += len;

	return 0;
}

/*
 * Correct errors in a block. Copies corrected block to dest if non-NULL,
 * otherwise to io->io_vec starting from provided vector and offset.
 */
int verity_fec_decode(struct dm_verity *v, struct dm_verity_io *io,
		      enum verity_block_type type, sector_t block, u8 *dest,
		      unsigned bv_vector, unsigned bv_offset)
{
	int r = -1;
	struct dm_verity_fec_io *fio = fec_io(io);
	u64 offset, res, rsb;

	if (!verity_fec_is_enabled(v))
		return -1;

	if (type == DM_VERITY_BLOCK_TYPE_METADATA)
		block += v->data_blocks;

	/*
	 * For RS(M, N), the continuous FEC data is divided into blocks of N
	 * bytes. Since block size may not be divisible by N, the last block
	 * is zero padded when decoding.
	 *
	 * Each byte of the block is covered by a different RS(M, N) code,
	 * and each code is interleaved over N blocks to make it less likely
	 * that bursty corruption will leave us in unrecoverable state.
	 */

	offset = block << v->data_dev_block_bits;

	res = offset;
	do_div(res, v->fec->rounds << v->data_dev_block_bits);

	/*
	 * The base RS block we can feed to the interleaver to find out all
	 * blocks required for decoding.
	 */
	rsb = offset - res * (v->fec->rounds << v->data_dev_block_bits);

	/*
	 * Locating erasures is slow, so attempt to recover the block without
	 * them first. Do a second attempt with erasures if the corruption is
	 * bad enough.
	 */
	r = fec_decode_rsb(v, io, fio, rsb, offset, 0);
	if (r < 0)
		r = fec_decode_rsb(v, io, fio, rsb, offset, 1);

	if (r < 0)
		return r;

	if (dest)
		memcpy(dest, fio->output, 1 << v->data_dev_block_bits);
	else {
		fio->output_pos = 0;
		r = verity_for_bv_block(v, io, &bv_vector, &bv_offset,
					fec_bv_copy);
	}

	return r;
}

/*
 * Clean up per-bio data.
 */
void verity_fec_finish_io(struct dm_verity_io *io, int error)
{
	unsigned n;
	struct dm_verity_fec *f = io->v->fec;
	struct dm_verity_fec_io *fio = fec_io(io);
	struct bio *bio = dm_bio_from_per_bio_data(io,
					io->v->ti->per_bio_data_size);

	if (!verity_fec_is_enabled(io->v))
		return;

	if (fio->rs)
		mempool_free(fio->rs, f->rs_pool);

	fec_for_each_prealloc_buffer(n)
		if (fio->bufs[n])
			mempool_free(fio->bufs[n], f->prealloc_pool);

	fec_for_each_extra_buffer(fio, n)
		if (fio->bufs[n])
			mempool_free(fio->bufs[n], f->extra_pool);

	if (fio->output)
		mempool_free(fio->output, f->output_pool);

	if (!error && !test_bit(BIO_UPTODATE, &bio->bi_flags))
		set_bit(BIO_UPTODATE, &bio->bi_flags);
}

/*
 * Initialize per-bio data.
 */
void verity_fec_init_io(struct dm_verity_io *io)
{
	struct dm_verity_fec_io *fio = fec_io(io);

	if (!verity_fec_is_enabled(io->v))
		return;

	fio->rs = NULL;
	memset(fio->bufs, 0, sizeof(fio->bufs));
	fio->nbufs = 0;
	fio->output = NULL;
}

/*
 * Append feature arguments and values to the status table.
 */
unsigned verity_fec_status_table(struct dm_verity *v, unsigned sz,
				 char *result, unsigned maxlen)
{
	if (!verity_fec_is_enabled(v))
		return sz;

	DMEMIT(" " DM_VERITY_OPT_FEC_DEV " %s "
	       DM_VERITY_OPT_FEC_BLOCKS " %llu "
	       DM_VERITY_OPT_FEC_START " %llu "
	       DM_VERITY_OPT_FEC_ROOTS " %d",
	       v->fec->dev->name,
	       (unsigned long long)v->fec->blocks,
	       (unsigned long long)v->fec->start,
	       v->fec->roots);

	return sz;
}

void verity_fec_dtr(struct dm_verity *v)
{
	struct dm_verity_fec *f = v->fec;

	if (!verity_fec_is_enabled(v))
		goto out;

	if (f->rs_pool)
		mempool_destroy(f->rs_pool);
	if (f->prealloc_pool)
		mempool_destroy(f->prealloc_pool);
	if (f->extra_pool)
		mempool_destroy(f->extra_pool);
	if (f->cache)
		kmem_cache_destroy(f->cache);

	if (f->data_bufio)
		dm_bufio_client_destroy(f->data_bufio);
	if (f->bufio)
		dm_bufio_client_destroy(f->bufio);

	if (f->dev)
		dm_put_device(v->ti, f->dev);

out:
	kfree(f);
	v->fec = NULL;
}

static void *fec_rs_alloc(gfp_t gfp_mask, void *pool_data)
{
	struct dm_verity *v = (struct dm_verity *)pool_data;

	return init_rs(8, 0x11d, 0, 1, v->fec->roots);
}

static void fec_rs_free(void *element, void *pool_data)
{
	struct rs_control *rs = (struct rs_control *)element;

	if (rs)
		free_rs(rs);
}

int verity_fec_parse_opt_args(struct dm_arg_set *as, struct dm_verity *v,
			      const char *opt_string)
{
	int r;
	unsigned long long num_ll;
	unsigned char num_c;
	char dummy;

	/* All feature arguments require a value */
	if (!as->argc)
		return -EINVAL;

	if (!strcasecmp(opt_string, DM_VERITY_OPT_FEC_DEV)) {
		r = dm_get_device(v->ti, dm_shift_arg(as), FMODE_READ,
					  &v->fec->dev);
		if (r) {
			v->ti->error = "FEC device lookup failed";
			return r;
		}

		return 1;
	} else if (!strcasecmp(opt_string, DM_VERITY_OPT_FEC_BLOCKS)) {
		if (sscanf(dm_shift_arg(as), "%llu%c", &num_ll, &dummy) != 1 ||
		    (sector_t)(num_ll <<
				(v->data_dev_block_bits - SECTOR_SHIFT))
		    >> (v->data_dev_block_bits - SECTOR_SHIFT) != num_ll) {
			v->ti->error = "Invalid " DM_VERITY_OPT_FEC_BLOCKS;
			return -EINVAL;
		}

		v->fec->blocks = num_ll;
		return 1;
	} else if (!strcasecmp(opt_string, DM_VERITY_OPT_FEC_START)) {
		if (sscanf(dm_shift_arg(as), "%llu%c", &num_ll, &dummy) != 1 ||
		    (sector_t)(num_ll <<
				(v->data_dev_block_bits - SECTOR_SHIFT))
		    >> (v->data_dev_block_bits - SECTOR_SHIFT) != num_ll) {
			v->ti->error = "Invalid " DM_VERITY_OPT_FEC_START;
			return -EINVAL;
		}

		v->fec->start = num_ll;
		return 1;
	} else if (!strcasecmp(opt_string, DM_VERITY_OPT_FEC_ROOTS)) {
		if (sscanf(dm_shift_arg(as), "%hhu%c", &num_c, &dummy) != 1 ||
		    !num_c ||
		    num_c < (DM_VERITY_FEC_RSM - DM_VERITY_FEC_MAX_RSN) ||
		    num_c > (DM_VERITY_FEC_RSM - DM_VERITY_FEC_MIN_RSN)) {
			v->ti->error = "Invalid " DM_VERITY_OPT_FEC_ROOTS;
			return -EINVAL;
		}

		v->fec->roots = num_c;
		return 1;
	}

	return -EINVAL;
}

/*
 * Allocate dm_verity_fec for v->fec. Must be called before verity_fec_ctr.
 */
int verity_fec_ctr_alloc(struct dm_verity *v)
{
	struct dm_verity_fec *f;

	f = kzalloc(sizeof(struct dm_verity_fec), GFP_KERNEL);
	if (!f) {
		v->ti->error = "Cannot allocate FEC structure";
		return -ENOMEM;
	}

	v->fec = f;
	return 0;
}

/*
 * Validate arguments and preallocate memory. Must be called after arguments
 * have been parsed using verity_fec_parse_opt_args.
 */
int verity_fec_ctr(struct dm_verity *v)
{
	struct dm_verity_fec *f = v->fec;
	u64 hash_blocks;

	if (!verity_fec_is_enabled(v)) {
		verity_fec_dtr(v);
		return 0;
	}

	/*
	 * FEC is computed over data blocks, possible metadata, and
	 * hash blocks. In other words, FEC covers total of fec_blocks
	 * blocks consisting of the following:
	 *
	 *  data blocks | hash blocks | metadata (optional)
	 *
	 * We allow metadata after hash blocks to support a use case
	 * where all data is stored on the same device and FEC covers
	 * the entire area.
	 *
	 * If metadata is included, we require it to be available on the
	 * hash device after the hash blocks.
	 */

	hash_blocks = v->hash_blocks - v->hash_start;

	/*
	 * Require matching block sizes for data and hash devices for
	 * simplicity.
	 */
	if (v->data_dev_block_bits != v->hash_dev_block_bits) {
		v->ti->error = "Block sizes must match to use FEC";
		return -EINVAL;
	}

	if (!f->roots) {
		v->ti->error = "Missing " DM_VERITY_OPT_FEC_ROOTS;
		return -EINVAL;
	}

	f->rsn = DM_VERITY_FEC_RSM - f->roots;

	if (!f->blocks) {
		v->ti->error = "Missing " DM_VERITY_OPT_FEC_BLOCKS;
		return -EINVAL;
	}

	f->rounds = f->blocks;

	if (do_div(f->rounds, f->rsn))
		f->rounds++;

	/*
	 * Due to optional metadata, f->blocks can be larger than
	 * data_blocks and hash_blocks combined.
	 */
	if (f->blocks < v->data_blocks + hash_blocks || !f->rounds) {
		v->ti->error = "Invalid " DM_VERITY_OPT_FEC_BLOCKS;
		return -EINVAL;
	}

	/*
	 * Metadata is accessed through the hash device, so we require
	 * it to be large enough.
	 */
	f->hash_blocks = f->blocks - v->data_blocks;

	if (dm_bufio_get_device_size(v->bufio) < f->hash_blocks) {
		v->ti->error = "Hash device is too small for "
				DM_VERITY_OPT_FEC_BLOCKS;
		return -E2BIG;
	}

	f->bufio = dm_bufio_client_create(f->dev->bdev,
				1 << v->data_dev_block_bits,
				1, 0, NULL, NULL);

	if (IS_ERR(f->bufio)) {
		v->ti->error = "Cannot initialize dm-bufio";
		return PTR_ERR(f->bufio);
	}

	if (dm_bufio_get_device_size(f->bufio) <
			(f->start + f->rounds * f->roots)
				>> v->data_dev_block_bits) {
		v->ti->error = "FEC device is too small";
		return -E2BIG;
	}

	f->data_bufio = dm_bufio_client_create(v->data_dev->bdev,
				1 << v->data_dev_block_bits,
				1, 0, NULL, NULL);

	if (IS_ERR(f->data_bufio)) {
		v->ti->error = "Cannot initialize dm-bufio";
		return PTR_ERR(f->data_bufio);
	}

	if (dm_bufio_get_device_size(f->data_bufio) < v->data_blocks) {
		v->ti->error = "Data device is too small";
		return -E2BIG;
	}

	/* Preallocate an rs_control structure for each worker thread */
	f->rs_pool = mempool_create(num_online_cpus(), fec_rs_alloc,
				fec_rs_free, (void *) v);

	if (!f->rs_pool) {
		v->ti->error = "Cannot allocate RS pool";
		return -ENOMEM;
	}

	f->cache = kmem_cache_create("dm_verity_fec_buffers",
				f->rsn << DM_VERITY_FEC_BUF_RS_BITS,
				0, 0, NULL);

	if (!f->cache) {
		v->ti->error = "Cannot create FEC buffer cache";
		return -ENOMEM;
	}

	/* Preallocate DM_VERITY_FEC_BUF_PREALLOC buffers for each thread */
	f->prealloc_pool = mempool_create_slab_pool(num_online_cpus() *
						DM_VERITY_FEC_BUF_PREALLOC,
					f->cache);

	if (!f->prealloc_pool) {
		v->ti->error = "Cannot allocate FEC buffer prealloc pool";
		return -ENOMEM;
	}

	f->extra_pool = mempool_create_slab_pool(0, f->cache);

	if (!f->extra_pool) {
		v->ti->error = "Cannot allocate FEC buffer extra pool";
		return -ENOMEM;
	}

	/* Preallocate an output buffer for each thread */
	f->output_pool = mempool_create_kmalloc_pool(num_online_cpus(),
					1 << v->data_dev_block_bits);

	if (!f->output_pool) {
		v->ti->error = "Cannot allocate FEC output pool";
		return -ENOMEM;
	}

	/* Reserve space for our per-bio data */
	v->ti->per_bio_data_size += sizeof(struct dm_verity_fec_io);

	return 0;
}
