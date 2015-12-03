#define DM_MAX_DEVICE_NAME 200
#define DM_MAX_KEY_IDENTIFIER 100

#define RSANUMBYTES 256
#define VERITY_METADATA_MAGIC_NUMBER 0xb001b001
#define VERITY_METADATA_MAGIC_DISABLE 0x46464f56
#define VERITY_STATE_DISABLE 1
#define DATA_BLOCK_SIZE (4 * 1024)
#define SECTOR_SIZE 512
#define VERITY_METADATA_SIZE (8 * DATA_BLOCK_SIZE)
#define VERITY_HEADER_SIZE 268
#define VERITY_TABLE_ARGS 10
#define MAX_CHARACTERS_FOR_UNSIGNED_64BIT 20
#define VERITY_TABLE_ARGS 10

#define SHA256_DIGEST_LENGTH 32
#define FEC_MAGIC 0xFECFECFE
#define FEC_BLOCK_SIZE (4 * 1024)

#define VERITY_DEBUG 0

enum verity_mode {
	VERITY_MODE_EIO = 0,
	VERITY_MODE_LOGGING = 1,
	VERITY_MODE_RESTART = 2,
	VERITY_MODE_LAST = VERITY_MODE_RESTART,
	VERITY_MODE_DEFAULT = VERITY_MODE_RESTART
};

int __init dm_setup(char *str);

static struct {
	char device_name[DM_MAX_DEVICE_NAME];
	char key_id[DM_MAX_KEY_IDENTIFIER];
} dm_verity_setup_args __initdata;

static struct metadata {
	u64 metadata_start;
	/*verity_table is freed before exiting init */
	char *verity_table;
	u32 magic_number;
	u32 protocol_version;
	u32 table_length;
	char signature[RSANUMBYTES];
} verity_metadata __initdata;

struct verity_state {
	u32 header;
	u32 version;
	s32 mode;
};

/*
 * There can be two formats.
 * if fec is present
 * <data_blocks> <verity_tree> <verity_metdata_32K><fec_data_4K>
 * if fec is not present
 * <data_blocks> <verity_tree> <verity_metdata_32K>
 */
/* TODO: rearrange structure to reduce memory holes
 * depends on userspace change.
 */
struct fec_header {
	u32 magic;
	u32 version;
	u32 size;
	u32 roots;
	u32 fec_size;
	u64 inp_size;
	u8 hash[SHA256_DIGEST_LENGTH];
};
