#define DM_VERITY_ENV_LENGTH            42
#define DM_VERITY_ENV_VAR_NAME          "VERITY_ERR_BLOCK_NR"

#define DM_VERITY_IO_VEC_INLINE         16
#define DM_VERITY_MEMPOOL_SIZE          4
#define DM_VERITY_DEFAULT_PREFETCH_SIZE 262144

#define DM_VERITY_MAX_LEVELS            63
#define DM_VERITY_MAX_CORRUPTED_ERRS    100

enum verity_mode {
	DM_VERITY_MODE_EIO = 0,
	DM_VERITY_MODE_LOGGING = 1,
	DM_VERITY_MODE_RESTART = 2,
	DM_VERITY_MODE_LAST = DM_VERITY_MODE_RESTART,
	DM_VERITY_MODE_DEFAULT = DM_VERITY_MODE_RESTART
};

enum verity_block_type {
	DM_VERITY_BLOCK_TYPE_DATA,
	DM_VERITY_BLOCK_TYPE_METADATA
};

struct dm_verity {
	struct dm_dev *data_dev;
	struct dm_dev *hash_dev;
	struct dm_target *ti;
	struct dm_bufio_client *bufio;
	char *alg_name;
	struct crypto_shash *tfm;
	u8 *root_digest;        /* digest of the root block */
	u8 *salt;               /* salt: its size is salt_size */
	unsigned salt_size;
	sector_t data_start;    /* data offset in 512-byte sectors */
	sector_t hash_start;    /* hash start in blocks */
	sector_t data_blocks;   /* the number of data blocks */
	sector_t hash_blocks;   /* the number of hash blocks */
	unsigned char data_dev_block_bits;      /* log2(data blocksize) */
	unsigned char hash_dev_block_bits;      /* log2(hash blocksize) */
	unsigned char hash_per_block_bits;      /* log2(hashes in hash block) */
	unsigned char levels;   /* the number of tree levels */
	unsigned char version;
	unsigned digest_size;   /* digest size for the current hash algorithm */
	unsigned shash_descsize;/* the size of temporary space for crypto */
	int hash_failed;        /* set to 1 if hash of any block failed */
	enum verity_mode mode;  /* mode for handling verification errors */
	unsigned corrupted_errs;/* Number of errors for corrupted blocks */

	mempool_t *vec_mempool; /* mempool of bio vector */

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

	/* A space for short vectors; longer vectors are allocated separately.*/
	struct bio_vec io_vec_inline[DM_VERITY_IO_VEC_INLINE];

	/*
	 * Three variably-size fields follow this struct:
	 *
	 * u8 hash_desc[v->shash_descsize];
	 * u8 real_digest[v->digest_size];
	 * u8 want_digest[v->digest_size];
	 *
	 * To access them use: io_hash_desc(), io_real_digest() and
	 * io_want_digest().
	 */
};

struct dm_verity_prefetch_work {
	struct work_struct work;
	struct dm_verity *v;
	sector_t block;
	unsigned n_blocks;
};

extern void verity_status(struct dm_target *ti, status_type_t type,
			unsigned status_flags, char *result, unsigned maxlen);
extern int verity_ioctl(struct dm_target *ti, unsigned cmd,
			unsigned long arg);
extern int verity_merge(struct dm_target *ti, struct bvec_merge_data *bvm,
			struct bio_vec *biovec, int max_size);
extern int verity_iterate_devices(struct dm_target *ti,
				iterate_devices_callout_fn fn, void *data);
extern void verity_io_hints(struct dm_target *ti, struct queue_limits *limits);
extern void verity_dtr(struct dm_target *ti);
extern int verity_ctr(struct dm_target *ti, unsigned argc, char **argv);
extern int verity_map(struct dm_target *ti, struct bio *bio);
