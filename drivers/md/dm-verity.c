/*
 * Copyright (C) 2012 Red Hat, Inc.
 * Copyright (C) 2015 Google, Inc.
 *
 * Author: Mikulas Patocka <mpatocka@redhat.com>
 *
 * Based on Chromium dm-verity driver (C) 2011 The Chromium OS Authors
 *
 * This file is released under the GPLv2.
 *
 * In the file "/sys/module/dm_verity/parameters/prefetch_cluster" you can set
 * default prefetch value. Data are read in "prefetch_cluster" chunks from the
 * hash device. Setting this greatly improves performance when data and hash
 * are on the same disk on different partitions on devices with poor random
 * access behavior.
 */

#include "dm-bufio.h"

#include <linux/module.h>
#include <linux/device-mapper.h>
#include <linux/reboot.h>
#include <linux/rslib.h>
#include <linux/vmalloc.h>
#include <crypto/hash.h>

#define DM_MSG_PREFIX			"verity"

#define DM_VERITY_ENV_LENGTH		42
#define DM_VERITY_ENV_VAR_NAME		"DM_VERITY_ERR_BLOCK_NR"

#define DM_VERITY_IO_VEC_INLINE		16
#define DM_VERITY_MEMPOOL_SIZE		4
#define DM_VERITY_DEFAULT_PREFETCH_SIZE	262144

#define DM_VERITY_MAX_LEVELS		63
#define DM_VERITY_MAX_CORRUPTED_ERRS	100

#define DM_VERITY_FEC_RSM		255

#define DM_VERITY_OPT_LOGGING		"ignore_corruption"
#define DM_VERITY_OPT_RESTART		"restart_on_corruption"

#define DM_VERITY_OPT_FEC_DEV		"use_fec_from_device"
#define DM_VERITY_OPT_FEC_BLOCKS	"fec_blocks"
#define DM_VERITY_OPT_FEC_START		"fec_start"
#define DM_VERITY_OPT_FEC_ROOTS		"fec_roots"

#define DM_VERITY_OPTS_FEC		8
#define DM_VERITY_OPTS_MAX		(1 + DM_VERITY_OPTS_FEC)

static unsigned dm_verity_prefetch_cluster = DM_VERITY_DEFAULT_PREFETCH_SIZE;

module_param_named(prefetch_cluster, dm_verity_prefetch_cluster, uint, S_IRUGO | S_IWUSR);

enum verity_mode {
	DM_VERITY_MODE_EIO,
	DM_VERITY_MODE_LOGGING,
	DM_VERITY_MODE_RESTART
};

enum verity_block_type {
	DM_VERITY_BLOCK_TYPE_DATA,
	DM_VERITY_BLOCK_TYPE_METADATA
};

struct dm_verity {
	struct dm_dev *data_dev;
	struct dm_dev *hash_dev;
	struct dm_dev *fec_dev;
	struct dm_target *ti;
	struct dm_bufio_client *data_bufio;
	struct dm_bufio_client *hash_bufio;
	struct dm_bufio_client *fec_bufio;
	char *alg_name;
	struct crypto_shash *tfm;
	u8 *root_digest;	/* digest of the root block */
	u8 *salt;		/* salt: its size is salt_size */
	unsigned salt_size;
	sector_t data_start;	/* data offset in 512-byte sectors */
	sector_t hash_start;	/* hash start in blocks */
	sector_t data_blocks;	/* the number of data blocks */
	sector_t hash_blocks;	/* the number of hash blocks */
	sector_t fec_start;	/* FEC data start in blocks */
	sector_t fec_blocks;	/* number of blocks covered by FEC */
	sector_t fec_rounds;	/* number of FEC rounds */
	sector_t fec_hash_blocks; /* blocks covered by FEC after hash_start */
	unsigned char data_dev_block_bits;	/* log2(data blocksize) */
	unsigned char hash_dev_block_bits;	/* log2(hash blocksize) */
	unsigned char hash_per_block_bits;	/* log2(hashes in hash block) */
	unsigned char levels;	/* the number of tree levels */
	unsigned char version;
	unsigned char fec_roots;/* number of parity bytes, M-N of RS(M, N) */
	unsigned char fec_rsn;	/* N of RS(M, N) */
	unsigned digest_size;	/* digest size for the current hash algorithm */
	unsigned shash_descsize;/* the size of temporary space for crypto */
	int hash_failed;	/* set to 1 if hash of any block failed */
	enum verity_mode mode;	/* mode for handling verification errors */
	unsigned corrupted_errs;/* Number of errors for corrupted blocks */

	mempool_t *vec_mempool;	/* mempool of bio vector */

	struct workqueue_struct *verify_wq;

	/* starting blocks for each tree level. 0 is the lowest level. */
	sector_t hash_level_block[DM_VERITY_MAX_LEVELS];
};

struct dm_verity_io {
	struct dm_verity *v;

	/* original values of bio->bi_end_io and bio->bi_private */
	bio_end_io_t *orig_bi_end_io;
	void *orig_bi_private;

	sector_t block;
	unsigned n_blocks;

	/* saved bio vector */
	struct bio_vec *io_vec;
	unsigned io_vec_size;

	struct work_struct work;

	/* A space for short vectors; longer vectors are allocated separately. */
	struct bio_vec io_vec_inline[DM_VERITY_IO_VEC_INLINE];

	struct rs_control *rs;
	int *erasures;
	size_t fec_pos;
	u8 *fec_buf;

	/*
	 * Three variably-size fields follow this struct:
	 *
	 * u8 hash_desc[v->shash_descsize];
	 * u8 real_digest[v->digest_size];
	 * u8 want_digest[v->digest_size];
	 *
	 * To access them use: io_hash_desc(), io_real_digest() and io_want_digest().
	 */
};

struct dm_verity_prefetch_work {
	struct work_struct work;
	struct dm_verity *v;
	sector_t block;
	unsigned n_blocks;
};

static struct shash_desc *io_hash_desc(struct dm_verity *v, struct dm_verity_io *io)
{
	return (struct shash_desc *)(io + 1);
}

static u8 *io_real_digest(struct dm_verity *v, struct dm_verity_io *io)
{
	return (u8 *)(io + 1) + v->shash_descsize;
}

static u8 *io_want_digest(struct dm_verity *v, struct dm_verity_io *io)
{
	return (u8 *)(io + 1) + v->shash_descsize + v->digest_size;
}

/*
 * Auxiliary structure appended to each dm-bufio buffer. If the value
 * hash_verified is nonzero, hash of the block has been verified.
 *
 * The variable hash_verified is set to 0 when allocating the buffer, then
 * it can be changed to 1 and it is never reset to 0 again.
 *
 * There is no lock around this value, a race condition can at worst cause
 * that multiple processes verify the hash of the same buffer simultaneously
 * and write 1 to hash_verified simultaneously.
 * This condition is harmless, so we don't need locking.
 */
struct buffer_aux {
	int hash_verified;
};

/*
 * Initialize struct buffer_aux for a freshly created buffer.
 */
static void dm_hash_bufio_alloc_callback(struct dm_buffer *buf)
{
	struct buffer_aux *aux = dm_bufio_get_aux_data(buf);

	aux->hash_verified = 0;
}

/*
 * Translate input sector number to the sector number on the target device.
 */
static sector_t verity_map_sector(struct dm_verity *v, sector_t bi_sector)
{
	return v->data_start + dm_target_offset(v->ti, bi_sector);
}

/*
 * Return hash position of a specified block at a specified tree level
 * (0 is the lowest level).
 * The lowest "hash_per_block_bits"-bits of the result denote hash position
 * inside a hash block. The remaining bits denote location of the hash block.
 */
static sector_t verity_position_at_level(struct dm_verity *v, sector_t block,
					 int level)
{
	return block >> (level * v->hash_per_block_bits);
}

/*
 * Wrapper for crypto_shash_init, which handles verity salting.
 */
static int verity_hash_init(struct dm_verity *v, struct shash_desc *desc)
{
	int r;

	desc->tfm = v->tfm;
	desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	r = crypto_shash_init(desc);

	if (unlikely(r < 0)) {
		DMERR("crypto_shash_init failed: %d", r);
		return r;
	}

	if (likely(v->version >= 1)) {
		r = crypto_shash_update(desc, v->salt, v->salt_size);

		if (unlikely(r < 0)) {
			DMERR("crypto_shash_update failed: %d", r);
			return r;
		}
	}

	return 0;
}

static int verity_hash_update(struct dm_verity *v, struct shash_desc *desc,
			      const u8 *data, size_t len)
{
	int r = crypto_shash_update(desc, data, len);

	if (unlikely(r < 0))
		DMERR("crypto_shash_update failed: %d", r);

	return r;
}

static int verity_hash_final(struct dm_verity *v, struct shash_desc *desc,
			     u8 *digest)
{
	int r;

	if (unlikely(!v->version)) {
		r = crypto_shash_update(desc, v->salt, v->salt_size);

		if (r < 0) {
			DMERR("crypto_shash_update failed: %d", r);
			return r;
		}
	}

	r = crypto_shash_final(desc, digest);

	if (unlikely(r < 0))
		DMERR("crypto_shash_final failed: %d", r);

	return r;
}

static int verity_hash(struct dm_verity *v, struct shash_desc *desc,
		       const u8 *data, size_t len, u8 *digest)
{
	int r;

	r = verity_hash_init(v, desc);
	if (unlikely(r < 0))
		return r;

	r = verity_hash_update(v, desc, data, len);
	if (unlikely(r < 0))
		return r;

	return verity_hash_final(v, desc, digest);
}

static void verity_hash_at_level(struct dm_verity *v, sector_t block, int level,
				 sector_t *hash_block, unsigned *offset)
{
	sector_t position = verity_position_at_level(v, block, level);
	unsigned idx;

	*hash_block = v->hash_level_block[level] + (position >> v->hash_per_block_bits);

	if (!offset)
		return;

	idx = position & ((1 << v->hash_per_block_bits) - 1);
	if (!v->version)
		*offset = idx * v->digest_size;
	else
		*offset = idx << (v->hash_dev_block_bits - v->hash_per_block_bits);
}

/*
 * Handle verification errors.
 */
static int verity_handle_err(struct dm_verity *v, enum verity_block_type type,
			     unsigned long long block)
{
	char verity_env[DM_VERITY_ENV_LENGTH];
	char *envp[] = { verity_env, NULL };
	const char *type_str = "";
	struct mapped_device *md = dm_table_get_md(v->ti->table);

	/* Corruption should be visible in device status in all modes */
	v->hash_failed = 1;

	if (v->corrupted_errs >= DM_VERITY_MAX_CORRUPTED_ERRS)
		goto out;

	v->corrupted_errs++;

	switch (type) {
	case DM_VERITY_BLOCK_TYPE_DATA:
		type_str = "data";
		break;
	case DM_VERITY_BLOCK_TYPE_METADATA:
		type_str = "metadata";
		break;
	default:
		BUG();
	}

	DMERR("%s: %s block %llu is corrupted", v->data_dev->name, type_str,
		block);

	if (v->corrupted_errs == DM_VERITY_MAX_CORRUPTED_ERRS)
		DMERR("%s: reached maximum errors", v->data_dev->name);

	snprintf(verity_env, DM_VERITY_ENV_LENGTH, "%s=%d,%llu",
		DM_VERITY_ENV_VAR_NAME, type, block);

	kobject_uevent_env(&disk_to_dev(dm_disk(md))->kobj, KOBJ_CHANGE, envp);

out:
	if (v->mode == DM_VERITY_MODE_LOGGING)
		return 0;

	if (v->mode == DM_VERITY_MODE_RESTART)
		kernel_restart("dm-verity device corrupted");

	return 1;
}

static int verity_fec_decode(struct dm_verity *v, struct dm_verity_io *io,
			     enum verity_block_type type, sector_t block,
			     u8 *dest, unsigned vector, unsigned offset);

/*
 * Verify hash of a metadata block pertaining to the specified data block
 * ("block" argument) at a specified level ("level" argument).
 *
 * On successful return, io_want_digest(v, io) contains the hash value for
 * a lower tree level or for the data block (if we're at the lowest leve).
 *
 * If "skip_unverified" is true, unverified buffer is skipped and 1 is returned.
 * If "skip_unverified" is false, unverified buffer is hashed and verified
 * against current value of io_want_digest(v, io).
 */
static int verity_verify_level(struct dm_verity *v, struct dm_verity_io *io,
			       sector_t block, int level, bool skip_unverified,
			       u8 *want_digest)
{
	struct dm_buffer *buf;
	struct buffer_aux *aux;
	u8 *data;
	int r;
	sector_t hash_block;
	unsigned offset;

	verity_hash_at_level(v, block, level, &hash_block, &offset);

	data = dm_bufio_read(v->hash_bufio, hash_block, &buf);
	if (unlikely(IS_ERR(data)))
		return PTR_ERR(data);

	aux = dm_bufio_get_aux_data(buf);

	if (!aux->hash_verified) {
		if (skip_unverified) {
			r = 1;
			goto release_ret_r;
		}

		r = verity_hash(v, io_hash_desc(v, io),
				data, 1 << v->hash_dev_block_bits,
				io_real_digest(v, io));
		if (unlikely(r < 0))
			goto release_ret_r;

		if (likely(memcmp(io_real_digest(v, io), want_digest,
				  v->digest_size) == 0))
			aux->hash_verified = 1;
		else if (verity_fec_decode(v, io,
					   DM_VERITY_BLOCK_TYPE_METADATA,
					   hash_block, data, 0, 0) == 0)
			aux->hash_verified = 1;
		else if (verity_handle_err(v,
					   DM_VERITY_BLOCK_TYPE_METADATA,
					   hash_block)) {
			r = -EIO;
			goto release_ret_r;
		}
	}

	data += offset;
	memcpy(want_digest, data, v->digest_size);
	r = 0;

release_ret_r:
	dm_bufio_release(buf);
	return r;
}

/*
 * Find a hash for a given block, write it to digest and verify the integrity
 * of the hash tree if necessary
 */
static int verity_hash_for_block(struct dm_verity *v, struct dm_verity_io *io,
				 sector_t block, u8 *digest)
{
	int i;
	int r;

	if (likely(v->levels)) {
		/*
		 * First, we try to get the requested hash for
		 * the current block. If the hash block itself is
		 * verified, zero is returned. If it isn't, this
		 * function returns 1 and we fall back to whole
		 * chain verification.
		 */
		r = verity_verify_level(v, io, block, 0, true, digest);
		if (likely(r <= 0))
			return r;
	}

	memcpy(digest, v->root_digest, v->digest_size);

	for (i = v->levels - 1; i >= 0; i--) {
		r = verity_verify_level(v, io, block, i, false, digest);
		if (unlikely(r))
			return r;
	}

	return 0;
}

/*
 * Calls function process for 1 << v->data_dev_block_bits bytes in io->io_vec
 * starting from (vector, offset). Assumes io->io_vec has enough data to
 * process.
 */
static int verity_for_bv_block(struct dm_verity *v, struct dm_verity_io *io,
			       unsigned *vector, unsigned *offset,
			       int (*process)(struct dm_verity *v,
					      struct dm_verity_io *io,
					      u8 *data, size_t len))
{
	unsigned todo = 1 << v->data_dev_block_bits;

	do {
		int r;
		struct bio_vec *bv;
		u8 *page;
		unsigned len;

		BUG_ON(*vector >= io->io_vec_size);
		bv = &io->io_vec[*vector];
		page = kmap_atomic(bv->bv_page);
		len = bv->bv_len - *offset;

		if (likely(len >= todo))
			len = todo;

		r = process(v, io, page + bv->bv_offset + *offset, len);
		kunmap_atomic(page);

		if (r < 0)
			return r;

		*offset += len;

		if (likely(*offset == bv->bv_len)) {
			*offset = 0;
			(*vector)++;
		}

		todo -= len;
	} while (todo);

	return 0;
}

static int verity_bv_hash_update(struct dm_verity *v, struct dm_verity_io *io,
				 u8 *data, size_t len)
{
	return verity_hash_update(v, io_hash_desc(v, io), data, len);
}

/*
 * Verify one "dm_verity_io" structure.
 */
static int verity_verify_io(struct dm_verity_io *io)
{
	struct dm_verity *v = io->v;
	unsigned b;
	unsigned vector = 0, offset = 0;
	unsigned start_vector, start_offset;

	for (b = 0; b < io->n_blocks; b++) {
		int r;
		struct shash_desc *desc = io_hash_desc(v, io);

		r = verity_hash_for_block(v, io, io->block + b,
					  io_want_digest(v, io));
		if (unlikely(r < 0))
			return r;

		r = verity_hash_init(v, desc);
		if (unlikely(r < 0))
			return r;

		start_vector = vector;
		start_offset = offset;

		r = verity_for_bv_block(v, io, &vector, &offset,
					verity_bv_hash_update);
		if (unlikely(r < 0))
			return r;

		r = verity_hash_final(v, desc, io_real_digest(v, io));
		if (unlikely(r < 0))
			return r;

		if (likely(memcmp(io_real_digest(v, io),
				  io_want_digest(v, io), v->digest_size) == 0))
			continue;
		else if (verity_fec_decode(v, io, DM_VERITY_BLOCK_TYPE_DATA,
					   io->block + b, NULL,
					   start_vector, start_offset) == 0)
			continue;
		else if (verity_handle_err(v, DM_VERITY_BLOCK_TYPE_DATA,
					   io->block + b))
			return -EIO;
	}
	BUG_ON(vector != io->io_vec_size);
	BUG_ON(offset);

	return 0;
}

/*
 * Returns an interleaved offset for a byte in RS block.
 */
static inline u64 verity_fec_interleave(struct dm_verity *v, u64 offset)
{
	u32 mod;

	mod = do_div(offset, v->fec_rsn);
	return offset + mod * (v->fec_rounds << v->data_dev_block_bits);
}

/*
 * Decode a block using Reed-Solomon.
 */
static int verity_fec_decode_rs8(struct dm_verity *v,
				 struct dm_verity_io *io, u8 *data, u8 *fec,
				 int neras)
{
	int i;
	uint16_t par[v->fec_roots];

	for (i = 0; i < v->fec_roots; i++)
		par[i] = fec[i];

	return decode_rs8(io->rs, data, par, v->fec_rsn, NULL, neras,
			  io->erasures, 0, NULL);
}

/*
 * Read error-correcting codes for the requested RS block. Returns a pointer
 * to the data block. Caller is responsible for releasing buf.
 */
static u8 *verity_fec_read_par(struct dm_verity *v, u64 rsb, int index,
			       unsigned *offset, struct dm_buffer **buf)
{
	u64 block;
	u8 *res;

	block = (index + rsb) * v->fec_roots >> v->data_dev_block_bits;

	*offset = (unsigned)((block << v->data_dev_block_bits) -
			     (index + rsb) * v->fec_roots);

	res = dm_bufio_read(v->fec_bufio, v->fec_start + block, buf);

	if (unlikely(IS_ERR(res))) {
		DMERR("%s: FEC %llu: parity read failed (block %llu): %ld",
		      v->data_dev->name, (unsigned long long)rsb,
		      (unsigned long long)(v->fec_start + block),
		      PTR_ERR(res));
		*buf = NULL;
		return NULL;
	}

	return res;
}

/*
 * Decode 1 << v->data_dev_block_bits FEC blocks from io->fec_buf and copy the
 * corrected 'index' block to the beginning of the buffer.
 */
static int verity_fec_decode_buf(struct dm_verity *v, struct dm_verity_io *io,
				 u64 rsb, int index, int neras)
{
	int corrected = 0;
	int i;
	int r = -1;
	int res;
	struct dm_buffer *buf;
	unsigned offset;
	u8 *par;

	par = verity_fec_read_par(v, rsb, 0, &offset, &buf);
	if (unlikely(!par))
		return r;

	for (i = 0; i < 1 << v->data_dev_block_bits; i++) {
		if (offset >= 1 << v->data_dev_block_bits) {
			dm_bufio_release(buf);

			par = verity_fec_read_par(v, rsb, i, &offset, &buf);
			if (unlikely(!par))
				return r;
		}

		res = verity_fec_decode_rs8(v, io,
				&io->fec_buf[i * v->fec_rsn], &par[offset],
				neras);

		if (res < 0)
			goto out;

		corrected += res;
		offset += v->fec_roots;

		/* copy corrected block to the beginning of fec_buf */
		io->fec_buf[i] = io->fec_buf[i * v->fec_rsn + index];
	}

	r = corrected;

out:
	dm_bufio_release(buf);

	if (r < 0 && neras)
		DMERR_LIMIT("%s: FEC %llu: failed to correct: %d",
			    v->data_dev->name, (unsigned long long)rsb, r);
	else if (r > 0)
		DMWARN_LIMIT("%s: FEC %llu: corrected %d errors",
			     v->data_dev->name, (unsigned long long)rsb, r);

	return r;
}

/*
 * Locate data block erasures using verity hashes.
 */
static int verity_fec_is_erasure(struct dm_verity *v, struct dm_verity_io *io,
				 u8 *want_digest, u8 *data)
{
	if (unlikely(verity_hash(v, io_hash_desc(v, io),
				 data, 1 << v->data_dev_block_bits,
				 io_real_digest(v, io))))
		return 0;

	return memcmp(io_real_digest(v, io), want_digest, v->digest_size) != 0;
}

/*
 * Read 1 << v->data_dev_block_bits interleaved FEC blocks into io->fec_buf
 * and check for erasure locations if neras is non-NULL.
 */
static int verity_fec_read_buf(struct dm_verity *v, struct dm_verity_io *io,
			       u64 rsb, u64 target, int *neras)
{
	int i;
	int j;
	int target_index = -1;
	struct dm_buffer *buf;
	struct dm_bufio_client *bufio;
	u64 block;
	u64 ileaved;
	u8 *bbuf;
	u8 want_digest[v->digest_size];

	if (neras)
		*neras = 0;

	for (i = 0; i < v->fec_rsn; i++) {
		ileaved = verity_fec_interleave(v, rsb * v->fec_rsn + i);

		if (ileaved == target)
			target_index = i;

		block = ileaved >> v->data_dev_block_bits;
		bufio = v->data_bufio;

		if (block >= v->data_blocks) {
			block -= v->data_blocks;

			if (unlikely(block >= v->fec_hash_blocks))
				continue;

			block += v->hash_start;
			bufio = v->hash_bufio;
		}

		bbuf = dm_bufio_read(bufio, block, &buf);

		if (unlikely(IS_ERR(bbuf))) {
			DMERR("%s: FEC %llu: read failed (block %llu): %ld",
			      v->data_dev->name, (unsigned long long)rsb,
			      (unsigned long long)block, PTR_ERR(bbuf));
			return -1;
		}

		if (block < v->data_blocks &&
		    verity_hash_for_block(v, io, block, want_digest) == 0) {
			if (neras && *neras <= v->fec_roots &&
			    verity_fec_is_erasure(v, io, want_digest, bbuf))
				io->erasures[(*neras)++] = i;
		}

		for (j = 0; j < 1 << v->data_dev_block_bits; j++)
			io->fec_buf[j * v->fec_rsn + i] = bbuf[j];

		dm_bufio_release(buf);
	}

	return target_index;
}

/*
 * Initialize Reed-Solomon and FEC buffers, and allocate them if needed.
 */
static int verity_fec_alloc_buffers(struct dm_verity *v,
				    struct dm_verity_io *io)
{
	size_t bufsize;

	if (!io->rs) {
		io->rs = init_rs(8, 0x11d, 0, 1, v->fec_roots);

		if (unlikely(!io->rs)) {
			DMERR("init_rs failed");
			return -ENOMEM;
		}
	}

	bufsize = v->fec_rsn << v->data_dev_block_bits;

	if (!io->fec_buf) {
		io->fec_buf = vzalloc(bufsize);

		if (unlikely(!io->fec_buf)) {
			DMERR("vzalloc failed (%zu bytes)", bufsize);
			return -ENOMEM;
		}
	} else
		memset(io->fec_buf, 0, bufsize);

	bufsize = v->fec_rsn * sizeof(int);

	if (!io->erasures) {
		io->erasures = kzalloc(bufsize, GFP_KERNEL);

		if (unlikely(!io->erasures)) {
			DMERR("kmalloc failed (%zu bytes)", bufsize);
			return -ENOMEM;
		}
	} else
		memset(io->erasures, 0, bufsize);

	return 0;
}

/*
 * Decode an interleaved RS block. If use_erasures is non-zero, uses hashes to
 * locate erasures. If returns zero, the corrected block is in the beginning of
 * io->fec_buf.
 */
static int verity_fec_decode_rsb(struct dm_verity *v,
				 struct dm_verity_io *io, u64 rsb,
				 u64 offset, int use_erasures)
{
	int r;
	int neras = 0;

	r = verity_fec_alloc_buffers(v, io);
	if (unlikely(r < 0))
		return -1;

	r = verity_fec_read_buf(v, io, rsb, offset,
				use_erasures ? &neras : NULL);
	if (unlikely(r < 0))
		return r;

	r = verity_fec_decode_buf(v, io, rsb, r, neras);
	if (r < 0)
		return r;

	r = verity_hash(v, io_hash_desc(v, io), io->fec_buf,
			1 << v->data_dev_block_bits, io_real_digest(v, io));
	if (unlikely(r < 0))
		return r;

	if (memcmp(io_real_digest(v, io), io_want_digest(v, io),
			v->digest_size)) {
		DMERR_LIMIT("%s: FEC %llu: failed to correct (%d erasures)",
			    v->data_dev->name, (unsigned long long)rsb, neras);
		return -1;
	}

	return 0;
}

static int verity_fec_bv_copy(struct dm_verity *v, struct dm_verity_io *io,
			      u8 *data, size_t len)
{
	BUG_ON(io->fec_pos + len > 1 << v->data_dev_block_bits);
	memcpy(data, &io->fec_buf[io->fec_pos], len);
	io->fec_pos += len;
	return 0;
}

/*
 * Correct errors in a block. Copies corrected block to dest if non-NULL,
 * otherwise to io->bio_vec starting from provided vector and offset.
 */
static int verity_fec_decode(struct dm_verity *v, struct dm_verity_io *io,
			     enum verity_block_type type, sector_t block,
			     u8 *dest, unsigned bv_vector, unsigned bv_offset)
{
	int r = -1;
	u64 offset;
	u64 res;
	u64 rsb;

	if (!v->fec_bufio)
		return -1;

	if (type == DM_VERITY_BLOCK_TYPE_METADATA)
		block += v->data_blocks;

	/*
	 * For RS(M, N), the continuous FEC data is divided into blocks of N
	 * bytes. Since block size may not be divisible by N, the last block
	 * is zero padded when decoding.
	 *
	 * Each byte of the block is covered by a different RS(255, N) code,
	 * and each code is interleaved over N blocks to make it less likely
	 * that bursty corruption will leave us in unrecoverable state.
	 */

	offset = block << v->data_dev_block_bits;

	res = offset;
	do_div(res, v->fec_rounds << v->data_dev_block_bits);

	/*
	 * The base RS block we can feed to the interleaver to find out all
	 * blocks required for decoding.
	 */
	rsb = offset - res * (v->fec_rounds << v->data_dev_block_bits);

	/*
	 * Locating erasures is slow, so attempt to recover the block without
	 * them first. Do a second attempt with erasures if the corruption is
	 * bad enough.
	 */
	r = verity_fec_decode_rsb(v, io, rsb, offset, 0);
	if (r < 0)
		r = verity_fec_decode_rsb(v, io, rsb, offset, 1);

	if (r < 0)
		return r;

	if (dest)
		memcpy(dest, io->fec_buf, 1 << v->hash_dev_block_bits);
	else {
		io->fec_pos = 0;
		r = verity_for_bv_block(v, io, &bv_vector, &bv_offset,
					verity_fec_bv_copy);
	}

	return r;
}


/*
 * End one "io" structure with a given error.
 */
static void verity_finish_io(struct dm_verity_io *io, int error)
{
	struct dm_verity *v = io->v;
	struct bio *bio = dm_bio_from_per_bio_data(io, v->ti->per_bio_data_size);

	bio->bi_end_io = io->orig_bi_end_io;
	bio->bi_private = io->orig_bi_private;

	if (io->io_vec != io->io_vec_inline)
		mempool_free(io->io_vec, v->vec_mempool);

	if (io->rs)
		free_rs(io->rs);

	if (io->fec_buf)
		vfree(io->fec_buf);

	kfree(io->erasures);

	bio_endio(bio, error);
}

static void verity_work(struct work_struct *w)
{
	struct dm_verity_io *io = container_of(w, struct dm_verity_io, work);

	verity_finish_io(io, verity_verify_io(io));
}

static void verity_end_io(struct bio *bio, int error)
{
	struct dm_verity_io *io = bio->bi_private;

	if (error) {
		verity_finish_io(io, error);
		return;
	}

	INIT_WORK(&io->work, verity_work);
	queue_work(io->v->verify_wq, &io->work);
}

/*
 * Prefetch buffers for the specified io.
 * The root buffer is not prefetched, it is assumed that it will be cached
 * all the time.
 */
static void verity_prefetch_io(struct work_struct *work)
{
	struct dm_verity_prefetch_work *pw =
		container_of(work, struct dm_verity_prefetch_work, work);
	struct dm_verity *v = pw->v;
	int i;

	for (i = v->levels - 2; i >= 0; i--) {
		sector_t hash_block_start;
		sector_t hash_block_end;
		verity_hash_at_level(v, pw->block, i, &hash_block_start, NULL);
		verity_hash_at_level(v, pw->block + pw->n_blocks - 1, i, &hash_block_end, NULL);
		if (!i) {
			unsigned cluster = ACCESS_ONCE(dm_verity_prefetch_cluster);

			cluster >>= v->data_dev_block_bits;
			if (unlikely(!cluster))
				goto no_prefetch_cluster;

			if (unlikely(cluster & (cluster - 1)))
				cluster = 1 << __fls(cluster);

			hash_block_start &= ~(sector_t)(cluster - 1);
			hash_block_end |= cluster - 1;
			if (unlikely(hash_block_end >= v->hash_blocks))
				hash_block_end = v->hash_blocks - 1;
		}
no_prefetch_cluster:
		dm_bufio_prefetch(v->hash_bufio, hash_block_start,
				  hash_block_end - hash_block_start + 1);
	}

	kfree(pw);
}

static void verity_submit_prefetch(struct dm_verity *v, struct dm_verity_io *io)
{
	struct dm_verity_prefetch_work *pw;

	pw = kmalloc(sizeof(struct dm_verity_prefetch_work),
		GFP_NOIO | __GFP_NORETRY | __GFP_NOMEMALLOC | __GFP_NOWARN);

	if (!pw)
		return;

	INIT_WORK(&pw->work, verity_prefetch_io);
	pw->v = v;
	pw->block = io->block;
	pw->n_blocks = io->n_blocks;
	queue_work(v->verify_wq, &pw->work);
}

/*
 * Bio map function. It allocates dm_verity_io structure and bio vector and
 * fills them. Then it issues prefetches and the I/O.
 */
static int verity_map(struct dm_target *ti, struct bio *bio)
{
	struct dm_verity *v = ti->private;
	struct dm_verity_io *io;

	bio->bi_bdev = v->data_dev->bdev;
	bio->bi_sector = verity_map_sector(v, bio->bi_sector);

	if (((unsigned)bio->bi_sector | bio_sectors(bio)) &
	    ((1 << (v->data_dev_block_bits - SECTOR_SHIFT)) - 1)) {
		DMERR_LIMIT("unaligned io");
		return -EIO;
	}

	if (bio_end_sector(bio) >>
	    (v->data_dev_block_bits - SECTOR_SHIFT) > v->data_blocks) {
		DMERR_LIMIT("io out of range");
		return -EIO;
	}

	if (bio_data_dir(bio) == WRITE)
		return -EIO;

	io = dm_per_bio_data(bio, ti->per_bio_data_size);
	io->v = v;
	io->orig_bi_end_io = bio->bi_end_io;
	io->orig_bi_private = bio->bi_private;
	io->block = bio->bi_sector >> (v->data_dev_block_bits - SECTOR_SHIFT);
	io->n_blocks = bio->bi_size >> v->data_dev_block_bits;

	bio->bi_end_io = verity_end_io;
	bio->bi_private = io;
	io->io_vec_size = bio_segments(bio);
	if (io->io_vec_size < DM_VERITY_IO_VEC_INLINE)
		io->io_vec = io->io_vec_inline;
	else
		io->io_vec = mempool_alloc(v->vec_mempool, GFP_NOIO);
	memcpy(io->io_vec, bio_iovec(bio),
	       io->io_vec_size * sizeof(struct bio_vec));

	io->rs = NULL;
	io->erasures = NULL;
	io->fec_buf = NULL;

	verity_submit_prefetch(v, io);

	generic_make_request(bio);

	return DM_MAPIO_SUBMITTED;
}

/*
 * Status: V (valid) or C (corruption found)
 */
static void verity_status(struct dm_target *ti, status_type_t type,
			  unsigned status_flags, char *result, unsigned maxlen)
{
	struct dm_verity *v = ti->private;
	unsigned args = 0;
	unsigned sz = 0;
	unsigned x;

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("%c", v->hash_failed ? 'C' : 'V');
		break;
	case STATUSTYPE_TABLE:
		DMEMIT("%u %s %s %u %u %llu %llu %s ",
			v->version,
			v->data_dev->name,
			v->hash_dev->name,
			1 << v->data_dev_block_bits,
			1 << v->hash_dev_block_bits,
			(unsigned long long)v->data_blocks,
			(unsigned long long)v->hash_start,
			v->alg_name
			);
		for (x = 0; x < v->digest_size; x++)
			DMEMIT("%02x", v->root_digest[x]);
		DMEMIT(" ");
		if (!v->salt_size)
			DMEMIT("-");
		else
			for (x = 0; x < v->salt_size; x++)
				DMEMIT("%02x", v->salt[x]);
		if (v->mode != DM_VERITY_MODE_EIO)
			args++;
		if (v->fec_dev)
			args += DM_VERITY_OPTS_FEC;
		if (!args)
			return;
		DMEMIT(" %u", args);
		if (v->mode != DM_VERITY_MODE_EIO) {
			DMEMIT(" ");
			switch (v->mode) {
			case DM_VERITY_MODE_LOGGING:
				DMEMIT(DM_VERITY_OPT_LOGGING);
				break;
			case DM_VERITY_MODE_RESTART:
				DMEMIT(DM_VERITY_OPT_RESTART);
				break;
			default:
				BUG();
			}
		}
		if (v->fec_dev)
			DMEMIT(" " DM_VERITY_OPT_FEC_DEV " %s "
			       DM_VERITY_OPT_FEC_BLOCKS " %llu "
			       DM_VERITY_OPT_FEC_START " %llu "
			       DM_VERITY_OPT_FEC_ROOTS " %d",
			       v->fec_dev->name,
			       (unsigned long long)v->fec_blocks,
			       (unsigned long long)v->fec_start,
			       v->fec_roots);
		break;
	}
}

static int verity_ioctl(struct dm_target *ti, unsigned cmd,
			unsigned long arg)
{
	struct dm_verity *v = ti->private;
	int r = 0;

	if (v->data_start ||
	    ti->len != i_size_read(v->data_dev->bdev->bd_inode) >> SECTOR_SHIFT)
		r = scsi_verify_blk_ioctl(NULL, cmd);

	return r ? : __blkdev_driver_ioctl(v->data_dev->bdev, v->data_dev->mode,
				     cmd, arg);
}

static int verity_merge(struct dm_target *ti, struct bvec_merge_data *bvm,
			struct bio_vec *biovec, int max_size)
{
	struct dm_verity *v = ti->private;
	struct request_queue *q = bdev_get_queue(v->data_dev->bdev);

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = v->data_dev->bdev;
	bvm->bi_sector = verity_map_sector(v, bvm->bi_sector);

	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static int verity_iterate_devices(struct dm_target *ti,
				  iterate_devices_callout_fn fn, void *data)
{
	struct dm_verity *v = ti->private;

	return fn(ti, v->data_dev, v->data_start, ti->len, data);
}

static void verity_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct dm_verity *v = ti->private;

	if (limits->logical_block_size < 1 << v->data_dev_block_bits)
		limits->logical_block_size = 1 << v->data_dev_block_bits;

	if (limits->physical_block_size < 1 << v->data_dev_block_bits)
		limits->physical_block_size = 1 << v->data_dev_block_bits;

	blk_limits_io_min(limits, limits->logical_block_size);
}

static void verity_dtr(struct dm_target *ti)
{
	struct dm_verity *v = ti->private;

	if (v->verify_wq)
		destroy_workqueue(v->verify_wq);

	if (v->vec_mempool)
		mempool_destroy(v->vec_mempool);

	if (v->data_bufio)
		dm_bufio_client_destroy(v->data_bufio);
	if (v->hash_bufio)
		dm_bufio_client_destroy(v->hash_bufio);
	if (v->fec_bufio)
		dm_bufio_client_destroy(v->fec_bufio);

	kfree(v->salt);
	kfree(v->root_digest);

	if (v->tfm)
		crypto_free_shash(v->tfm);

	kfree(v->alg_name);

	if (v->data_dev)
		dm_put_device(ti, v->data_dev);
	if (v->hash_dev)
		dm_put_device(ti, v->hash_dev);
	if (v->fec_dev)
		dm_put_device(ti, v->fec_dev);

	kfree(v);
}

static int verity_parse_opt_args(struct dm_arg_set *as, struct dm_verity *v,
				 const char *opt_string)
{
	int r;
	unsigned long long num_ll;
	unsigned char num_c;
	char dummy;

	if (!strcasecmp(opt_string, DM_VERITY_OPT_LOGGING)) {
		v->mode = DM_VERITY_MODE_LOGGING;
		return 0;
	} else if (!strcasecmp(opt_string, DM_VERITY_OPT_RESTART)) {
		v->mode = DM_VERITY_MODE_RESTART;
		return 0;
	}

	/* Remaining arguments require a value */
	if (!as->argc)
		goto bad;

	if (!strcasecmp(opt_string, DM_VERITY_OPT_FEC_DEV)) {
		r = dm_get_device(v->ti, dm_shift_arg(as), FMODE_READ,
					  &v->fec_dev);
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

		v->fec_blocks = num_ll;
		return 1;
	} else if (!strcasecmp(opt_string, DM_VERITY_OPT_FEC_START)) {
		if (sscanf(dm_shift_arg(as), "%llu%c", &num_ll, &dummy) != 1 ||
		    (sector_t)(num_ll <<
				(v->data_dev_block_bits - SECTOR_SHIFT))
		    >> (v->data_dev_block_bits - SECTOR_SHIFT) != num_ll) {
			v->ti->error = "Invalid " DM_VERITY_OPT_FEC_START;
			return -EINVAL;
		}

		v->fec_start = num_ll;
		return 1;
	} else if (!strcasecmp(opt_string, DM_VERITY_OPT_FEC_ROOTS)) {
		if (sscanf(dm_shift_arg(as), "%hhu%c", &num_c, &dummy) != 1 ||
		    !num_c || num_c >= DM_VERITY_FEC_RSM) {
			v->ti->error = "Invalid " DM_VERITY_OPT_FEC_ROOTS;
			return -EINVAL;
		}

		v->fec_roots = num_c;
		return 1;
	}

bad:
	v->ti->error = "Invalid feature arguments";
	return -EINVAL;
}

/*
 * Target parameters:
 *	<version>	The current format is version 1.
 *			Vsn 0 is compatible with original Chromium OS releases.
 *	<data device>
 *	<hash device>
 *	<data block size>
 *	<hash block size>
 *	<the number of data blocks>
 *	<hash start block>
 *	<algorithm>
 *	<digest>
 *	<salt>		Hex string or "-" if no salt.
 */
static int verity_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	struct dm_verity *v;
	struct dm_arg_set as;
	const char *opt_string;
	unsigned int num, opt_params;
	unsigned long long num_ll;
	int r;
	int i;
	sector_t hash_position;
	char dummy;

	static struct dm_arg _args[] = {
		{0, DM_VERITY_OPTS_MAX, "Invalid number of feature args"},
	};

	v = kzalloc(sizeof(struct dm_verity), GFP_KERNEL);
	if (!v) {
		ti->error = "Cannot allocate verity structure";
		return -ENOMEM;
	}
	ti->private = v;
	v->ti = ti;

	if ((dm_table_get_mode(ti->table) & ~FMODE_READ)) {
		ti->error = "Device must be readonly";
		r = -EINVAL;
		goto bad;
	}

	if (argc < 10) {
		ti->error = "Not enough arguments";
		r = -EINVAL;
		goto bad;
	}

	if (sscanf(argv[0], "%u%c", &num, &dummy) != 1 ||
	    num > 1) {
		ti->error = "Invalid version";
		r = -EINVAL;
		goto bad;
	}
	v->version = num;

	r = dm_get_device(ti, argv[1], FMODE_READ, &v->data_dev);
	if (r) {
		ti->error = "Data device lookup failed";
		goto bad;
	}

	r = dm_get_device(ti, argv[2], FMODE_READ, &v->hash_dev);
	if (r) {
		ti->error = "Data device lookup failed";
		goto bad;
	}

	if (sscanf(argv[3], "%u%c", &num, &dummy) != 1 ||
	    !num || (num & (num - 1)) ||
	    num < bdev_logical_block_size(v->data_dev->bdev) ||
	    num > PAGE_SIZE) {
		ti->error = "Invalid data device block size";
		r = -EINVAL;
		goto bad;
	}
	v->data_dev_block_bits = __ffs(num);

	if (sscanf(argv[4], "%u%c", &num, &dummy) != 1 ||
	    !num || (num & (num - 1)) ||
	    num < bdev_logical_block_size(v->hash_dev->bdev) ||
	    num > INT_MAX) {
		ti->error = "Invalid hash device block size";
		r = -EINVAL;
		goto bad;
	}
	v->hash_dev_block_bits = __ffs(num);

	if (sscanf(argv[5], "%llu%c", &num_ll, &dummy) != 1 ||
	    (sector_t)(num_ll << (v->data_dev_block_bits - SECTOR_SHIFT))
	    >> (v->data_dev_block_bits - SECTOR_SHIFT) != num_ll) {
		ti->error = "Invalid data blocks";
		r = -EINVAL;
		goto bad;
	}
	v->data_blocks = num_ll;

	if (ti->len > (v->data_blocks << (v->data_dev_block_bits - SECTOR_SHIFT))) {
		ti->error = "Data device is too small";
		r = -EINVAL;
		goto bad;
	}

	if (sscanf(argv[6], "%llu%c", &num_ll, &dummy) != 1 ||
	    (sector_t)(num_ll << (v->hash_dev_block_bits - SECTOR_SHIFT))
	    >> (v->hash_dev_block_bits - SECTOR_SHIFT) != num_ll) {
		ti->error = "Invalid hash start";
		r = -EINVAL;
		goto bad;
	}
	v->hash_start = num_ll;

	v->alg_name = kstrdup(argv[7], GFP_KERNEL);
	if (!v->alg_name) {
		ti->error = "Cannot allocate algorithm name";
		r = -ENOMEM;
		goto bad;
	}

	v->tfm = crypto_alloc_shash(v->alg_name, 0, 0);
	if (IS_ERR(v->tfm)) {
		ti->error = "Cannot initialize hash function";
		r = PTR_ERR(v->tfm);
		v->tfm = NULL;
		goto bad;
	}
	v->digest_size = crypto_shash_digestsize(v->tfm);
	if ((1 << v->hash_dev_block_bits) < v->digest_size * 2) {
		ti->error = "Digest size too big";
		r = -EINVAL;
		goto bad;
	}
	v->shash_descsize =
		sizeof(struct shash_desc) + crypto_shash_descsize(v->tfm);

	v->root_digest = kmalloc(v->digest_size, GFP_KERNEL);
	if (!v->root_digest) {
		ti->error = "Cannot allocate root digest";
		r = -ENOMEM;
		goto bad;
	}
	if (strlen(argv[8]) != v->digest_size * 2 ||
	    hex2bin(v->root_digest, argv[8], v->digest_size)) {
		ti->error = "Invalid root digest";
		r = -EINVAL;
		goto bad;
	}

	if (strcmp(argv[9], "-")) {
		v->salt_size = strlen(argv[9]) / 2;
		v->salt = kmalloc(v->salt_size, GFP_KERNEL);
		if (!v->salt) {
			ti->error = "Cannot allocate salt";
			r = -ENOMEM;
			goto bad;
		}
		if (strlen(argv[9]) != v->salt_size * 2 ||
		    hex2bin(v->salt, argv[9], v->salt_size)) {
			ti->error = "Invalid salt";
			r = -EINVAL;
			goto bad;
		}
	}

	argv += 10;
	argc -= 10;

	/* Optional parameters */
	if (argc) {
		as.argc = argc;
		as.argv = argv;

		r = dm_read_arg_group(_args, &as, &opt_params, &ti->error);
		if (r)
			goto bad;

		while (opt_params) {
			opt_params--;
			opt_string = dm_shift_arg(&as);
			if (!opt_string) {
				ti->error = "Not enough feature arguments";
				r = -EINVAL;
				goto bad;
			}

			r = verity_parse_opt_args(&as, v, opt_string);
			if (r < 0)
				goto bad;

			opt_params -= r;
		}
	}

	v->hash_per_block_bits =
		__fls((1 << v->hash_dev_block_bits) / v->digest_size);

	v->levels = 0;
	if (v->data_blocks)
		while (v->hash_per_block_bits * v->levels < 64 &&
		       (unsigned long long)(v->data_blocks - 1) >>
		       (v->hash_per_block_bits * v->levels))
			v->levels++;

	if (v->levels > DM_VERITY_MAX_LEVELS) {
		ti->error = "Too many tree levels";
		r = -E2BIG;
		goto bad;
	}

	hash_position = v->hash_start;
	for (i = v->levels - 1; i >= 0; i--) {
		sector_t s;
		v->hash_level_block[i] = hash_position;
		s = (v->data_blocks + ((sector_t)1 << ((i + 1) * v->hash_per_block_bits)) - 1)
					>> ((i + 1) * v->hash_per_block_bits);
		if (hash_position + s < hash_position) {
			ti->error = "Hash device offset overflow";
			r = -E2BIG;
			goto bad;
		}
		hash_position += s;
	}
	v->hash_blocks = hash_position;

	v->hash_bufio = dm_bufio_client_create(v->hash_dev->bdev,
		1 << v->hash_dev_block_bits, 1, sizeof(struct buffer_aux),
		dm_hash_bufio_alloc_callback, NULL);
	if (IS_ERR(v->hash_bufio)) {
		ti->error = "Cannot initialize dm-bufio for hash device";
		r = PTR_ERR(v->hash_bufio);
		v->hash_bufio = NULL;
		goto bad;
	}

	if (dm_bufio_get_device_size(v->hash_bufio) < v->hash_blocks) {
		ti->error = "Hash device is too small";
		r = -E2BIG;
		goto bad;
	}

	ti->per_bio_data_size = roundup(sizeof(struct dm_verity_io) + v->shash_descsize + v->digest_size * 2, __alignof__(struct dm_verity_io));

	v->vec_mempool = mempool_create_kmalloc_pool(DM_VERITY_MEMPOOL_SIZE,
					BIO_MAX_PAGES * sizeof(struct bio_vec));
	if (!v->vec_mempool) {
		ti->error = "Cannot allocate vector mempool";
		r = -ENOMEM;
		goto bad;
	}

	/* WQ_UNBOUND greatly improves performance when running on ramdisk */
	v->verify_wq = alloc_workqueue("kverityd", WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM | WQ_UNBOUND, num_online_cpus());
	if (!v->verify_wq) {
		ti->error = "Cannot allocate workqueue";
		r = -ENOMEM;
		goto bad;
	}

	if (v->fec_dev) {
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

		u64 hash_blocks = v->hash_blocks - v->hash_start;

		/*
		 * Require matching block sizes for data and hash devices for
		 * simplicity.
		 */
		if (v->data_dev_block_bits != v->hash_dev_block_bits) {
			ti->error = "Block sizes must match to use FEC";
			r = -EINVAL;
			goto bad;
		}

		if (!v->fec_roots) {
			ti->error = "Missing " DM_VERITY_OPT_FEC_ROOTS;
			r = -EINVAL;
			goto bad;
		}

		v->fec_rsn = DM_VERITY_FEC_RSM - v->fec_roots;

		if (!v->fec_blocks) {
			ti->error = "Missing " DM_VERITY_OPT_FEC_BLOCKS;
			r = -EINVAL;
			goto bad;
		}

		v->fec_rounds = v->fec_blocks;

		if (do_div(v->fec_rounds, v->fec_rsn))
			v->fec_rounds++;

		/*
		 * Due to optional metadata, fec_blocks can be larger than
		 * data_blocks and hash_blocks combined.
		 */
		if (v->fec_blocks < v->data_blocks + hash_blocks ||
				!v->fec_rounds) {
			ti->error = "Invalid " DM_VERITY_OPT_FEC_BLOCKS;
			r = -EINVAL;
			goto bad;
		}

		/*
		 * Metadata is accessed through the hash device, so we require
		 * it to be large enough.
		 */
		v->fec_hash_blocks = v->fec_blocks - v->data_blocks;

		if (dm_bufio_get_device_size(v->hash_bufio) <
				v->fec_hash_blocks) {
			ti->error = "Hash device is too small for "
					DM_VERITY_OPT_FEC_BLOCKS;
			r = -E2BIG;
			goto bad;
		}

		v->fec_bufio = dm_bufio_client_create(v->fec_dev->bdev,
					1 << v->data_dev_block_bits,
					1, 0, NULL, NULL);

		if (IS_ERR(v->fec_bufio)) {
			ti->error = "Cannot initialize dm-bufio";
			r = PTR_ERR(v->fec_bufio);
			v->fec_bufio = NULL;
			goto bad;
		}

		if (dm_bufio_get_device_size(v->fec_bufio) <
				(v->fec_start + v->fec_rounds * v->fec_roots)
				>> v->data_dev_block_bits) {
			ti->error = "FEC device is too small";
			r = -E2BIG;
			goto bad;
		}

		v->data_bufio = dm_bufio_client_create(v->data_dev->bdev,
					1 << v->data_dev_block_bits,
					1, 0, NULL, NULL);

		if (IS_ERR(v->data_bufio)) {
			ti->error = "Cannot initialize dm-bufio";
			r = PTR_ERR(v->data_bufio);
			v->data_bufio = NULL;
			goto bad;
		}

		if (dm_bufio_get_device_size(v->data_bufio) < v->data_blocks) {
			ti->error = "Data device is too small";
			r = -E2BIG;
			goto bad;
		}
	}

	return 0;

bad:
	verity_dtr(ti);

	return r;
}

static struct target_type verity_target = {
	.name		= "verity",
	.version	= {1, 2, 0},
	.module		= THIS_MODULE,
	.ctr		= verity_ctr,
	.dtr		= verity_dtr,
	.map		= verity_map,
	.status		= verity_status,
	.ioctl		= verity_ioctl,
	.merge		= verity_merge,
	.iterate_devices = verity_iterate_devices,
	.io_hints	= verity_io_hints,
};

static int __init dm_verity_init(void)
{
	int r;

	r = dm_register_target(&verity_target);
	if (r < 0)
		DMERR("register failed %d", r);

	return r;
}

static void __exit dm_verity_exit(void)
{
	dm_unregister_target(&verity_target);
}

module_init(dm_verity_init);
module_exit(dm_verity_exit);

MODULE_AUTHOR("Mikulas Patocka <mpatocka@redhat.com>");
MODULE_AUTHOR("Mandeep Baines <msb@chromium.org>");
MODULE_AUTHOR("Will Drewry <wad@chromium.org>");
MODULE_AUTHOR("Sami Tolvanen <samitolvanen@google.com>");
MODULE_DESCRIPTION(DM_NAME " target for transparent disk integrity checking");
MODULE_LICENSE("GPL");
