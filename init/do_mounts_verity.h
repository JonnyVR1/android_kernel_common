#define PRINT_TAG "Verity_setup: "

/* Forces printk strings into init.rodata section.
 * Only meant to be used in functions annotated with __init
 * Linker might not complain if abused.
 */
#define pr_init_info(fmt, ...) ({\
static const char __fmt[] __initconst = KERN_INFO PRINT_TAG fmt; \
printk(__fmt, ##__VA_ARGS__); })

#define pr_init_err(fmt, ...) ({\
static const char __fmt[] __initconst = KERN_ERR PRINT_TAG fmt; \
printk(__fmt, ##__VA_ARGS__); })

#define pr_init_debug(fmt, ...) ({\
static const char __fmt[] __initconst = PRINT_TAG fmt; \
pr_debug(__fmt, ##__VA_ARGS__); })

#define DM_NO_UUID "none"
#define DM_MAX_NAME 32
#define DM_MAX_UUID 129

#ifdef CONFIG_ROOTDEV_ANDROID_VERITY
struct dm_setup_verity * __init verity_run_setup(const char *rootdev);
#else
static struct dm_setup_verity * __init verity_run_setup(const char *rootdev)
{ return ERR_PTR(-ENOTSUPP); }
#endif

struct dm_setup_target {
	sector_t begin;
	sector_t length;
	char *type;
	char *params;
	/* simple singly linked list */
	struct dm_setup_target *next;
};

struct dm_setup_verity {
	int minor;
	int ro;
	char name[DM_MAX_NAME];
	char uuid[DM_MAX_UUID];
	struct dm_setup_target *target;
	int target_count;
	/* callback to the client for freeing allocated memory.
	 * Also informs client of failure by setting
	 * the err variable.
	 */
	void (*verity_setup_done)(bool err);
};
