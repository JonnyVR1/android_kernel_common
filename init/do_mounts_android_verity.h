#define DM_FIELD_SEP '#'
#define DM_MSG_PREFIX "init"
#define DM_MAX_FILE_SYSTEM 10
#define DM_MAX_DEVICE_NAME 200
#define DM_MAX_KEY_IDENTIFIER 100

#define RSANUMBYTES 256
#define METADATA_TAG_MAX_LENGTH 63
#define METADATA_MAGIC 0x01564c54
#define VERITY_STATE_TAG "verity_state"
#define VERITY_LASTSIG_TAG "verity_lastsig"
#define METADATA_EOD "eod"

#define VERITY_STATE_HEADER 0x83c0ae9d
#define VERITY_STATE_VERSION 1

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
	u32 magic_number;
	u32 protocol_version;
	char signature[RSANUMBYTES];
	u32 table_length;
	u64 metadata_start;
	char *verity_table;
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

struct fec_header {
	u32 magic;
	u32 version;
	u32 size;
	u32 roots;
	u32 fec_size;
	u64 inp_size;
	u8 hash[SHA256_DIGEST_LENGTH];
};
