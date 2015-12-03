/*
 * Copyright (C) 2015 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/async.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/device-mapper.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/key.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/reboot.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/vmalloc.h>

#include <asm/setup.h>
#include <crypto/hash.h>
#include <crypto/public_key.h>
#include <crypto/sha.h>
#include <keys/asymmetric-type.h>
#include <keys/system_keyring.h>

#include "do_mounts.h"
#include "do_mounts_android_verity.h"
#include "do_mounts_verity.h"

static int verity_early_setup __initdata;

static int __init dm_verity_setup(char *str)
{
	strncpy(dm_verity_setup_args.key_id, str, DM_MAX_KEY_IDENTIFIER);
	dm_verity_setup_args.key_id[DM_MAX_KEY_IDENTIFIER-1] = '\0';
	verity_early_setup = 1;
	return 1;
}
__setup("dm_verity=", dm_verity_setup);

static int __init table_extract_mpi_array(struct public_key_signature *pks,
					const void *data, size_t len)
{
	MPI mpi = mpi_read_raw_data(data, len);

	if (!mpi) {
		pr_init_err("no memory\n");
		return -ENOMEM;
	}

	pks->mpi[0] = mpi;
	pks->nr_mpi = 1;
	return 0;
}

static struct public_key_signature * __init table_make_digest(
						enum pkey_hash_algo hash,
						const void *table,
						unsigned long table_len)
{
	struct public_key_signature *pks;
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	size_t digest_size, desc_size;
	int ret;

	/* Allocate the hashing algorithm we're going to need and find out how
	 * big the hash operational data will be.
	 */
	tfm = crypto_alloc_shash(pkey_hash_algo[hash], 0, 0);
	if (IS_ERR(tfm))
		return (PTR_ERR(tfm) == -ENOENT) ? ERR_PTR(-ENOPKG) :
						ERR_CAST(tfm);

	desc_size = crypto_shash_descsize(tfm) + sizeof(*desc);
	digest_size = crypto_shash_digestsize(tfm);

	/* We allocate the hash operational data storage on the end of our
	 * context data and the digest output buffer on the end of that.
	 */
	ret = -ENOMEM;
	pks = kzalloc(digest_size + sizeof(*pks) + desc_size, GFP_KERNEL);
	if (!pks)
		goto error_no_pks;

	pks->pkey_hash_algo = hash;
	pks->digest = (u8 *)pks + sizeof(*pks) + desc_size;
	pks->digest_size = digest_size;

	desc = (struct shash_desc *)(pks + 1);
	desc->tfm = tfm;
	desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	ret = crypto_shash_init(desc);
	if (ret < 0)
		goto error;

	ret = crypto_shash_finup(desc, table, table_len, pks->digest);
	if (ret < 0)
		goto error;

	crypto_free_shash(tfm);
	return pks;

error:
	kfree(pks);
error_no_pks:
	crypto_free_shash(tfm);
	return ERR_PTR(ret);
}

static int __init verify_verity_signature(void)
{
	key_ref_t key_ref;
	struct key *key;
	struct public_key_signature *pks;
	int retval = -EINVAL;

	key_ref = keyring_search(make_key_ref(system_trusted_keyring, 1),
			&key_type_asymmetric, dm_verity_setup_args.key_id);

	if (IS_ERR(key_ref)) {
		pr_init_err("keyring: key not found");
		return -ENOKEY;
	}

	key = key_ref_to_ptr(key_ref);

	pks = table_make_digest(PKEY_HASH_SHA256,
			(const void *)verity_metadata.verity_table,
			verity_metadata.table_length);

	if (IS_ERR(pks)) {
		pr_init_err("hashing failed\n");
		goto error_no_pks;
	}

	retval = table_extract_mpi_array(pks, &verity_metadata.signature[0],
					RSANUMBYTES);
	if (retval < 0) {
		pr_init_err("Error extracting mpi %d\n", retval);
		goto error;
	}

	retval = verify_signature(key, pks);
	mpi_free(pks->rsa.s);
error:
	kfree(pks);
error_no_pks:
	key_put(key);

	return retval;
}


static int __init verity_create_dev(char *dev_name)
{
	int i;
	dev_t DEV = name_to_dev_t(dev_name);

	if (DEV == 0) {
		pr_init_info("%s: Waiting for device %s...\n", __func__,
			dev_name);
		for (i = 0; i <= 100 && ((driver_probe_done() != 0) ||
			    (DEV == 0)); i++) {
			msleep(100);
			DEV = name_to_dev_t(dev_name);
		}
		async_synchronize_full();
	}

	if (DEV == 0)
		return -ENODEV;

	pr_init_info("%s: Root device found. dev_t %u %u\n", __func__,
		MAJOR(DEV), MINOR(DEV));
	return create_dev(dev_name, DEV);
}

static int __init get_metadata_offset(u64 *offset)
{
	dev_t DEV = name_to_dev_t(dm_verity_setup_args.device_name);
	struct block_device *bdev = bdget(DEV);
	int block_fd, retval = 0;
	u64 device_size;
	struct fec_header fec;
	long long ret;

	if (bdev == NULL)
		return -EINVAL;

	device_size = i_size_read(bdev->bd_inode);
	bdput(bdev);

	block_fd = sys_open(dm_verity_setup_args.device_name, O_RDONLY, 0);

	if (block_fd < 0) {
		pr_init_err("Unable to open root device %s\n",
			dm_verity_setup_args.device_name);
		return -EIO;
	}

	ret = sys_lseek(block_fd, device_size - FEC_BLOCK_SIZE, 0);
	if (ret != device_size - FEC_BLOCK_SIZE) {
		pr_init_err("Unable to seek to metadata start\n");
		retval = -EIO;
		goto error;
	}

	ret = sys_read(block_fd, (unsigned char *)&fec,
		sizeof(fec));
	if (ret != sizeof(fec)) {
		pr_init_err("Unable to read fec_header: %zu bytes\n",
			sizeof(fec));
		retval = -EIO;
		goto error;
	}

	if (fec.magic == FEC_MAGIC)
		*offset = fec.inp_size - VERITY_METADATA_SIZE;
	else
		*offset = device_size - VERITY_METADATA_SIZE;
	retval = 0;
error:
	sys_close(block_fd);
	return retval;
}

static bool __init is_unlocked(void)
{
	char *verifiedboot;
	static const char bootstate[] __initconst =
				"androidboot.verifiedbootstate=";
	static const char unlocked[] __initconst = "orange";

	verifiedboot = strnstr(saved_command_line, bootstate,
						COMMAND_LINE_SIZE);
	if (verifiedboot == NULL)
		return false;

	verifiedboot = verifiedboot + sizeof(bootstate) - 1;

	return !strncmp(verifiedboot, unlocked, sizeof(unlocked) - 1);
}

static int __init verity_mode(void)
{
	char *veritymode;
	static const char veritymodeprop[] __initconst =
					"androidboot.veritymode=";
	static const char enforcing[] __initconst = "enforcing";
	static const char logging[] __initconst = "logging";

	veritymode = strnstr(saved_command_line, veritymodeprop,
			COMMAND_LINE_SIZE);
	if (veritymode == NULL)
		return VERITY_MODE_EIO;

	veritymode = veritymode + sizeof(veritymodeprop) - 1;

	if (!strncmp(veritymode, enforcing, sizeof(enforcing) - 1))
		return VERITY_MODE_RESTART;

	if (!strncmp(veritymode, logging, sizeof(logging) - 1))
		return VERITY_MODE_LOGGING;

	return VERITY_MODE_EIO;
}

static int __init extract_metadata(void)
{
	int retval = -EFAULT;
	int block_fd;
	long long ret;
	__le32 parameter;

	verity_metadata.verity_table = NULL;
	block_fd = sys_open(dm_verity_setup_args.device_name, O_RDONLY, 0);

	if (block_fd < 0) {
		pr_init_err("Unable to open root device %s\n",
			dm_verity_setup_args.device_name);
		return retval;
	}

	/* Find the offset of metadata */
	if (get_metadata_offset(&verity_metadata.metadata_start)) {
		pr_init_err("Error finding device size\n");
		goto error;
	}

	pr_init_info("metadata offset = %llu\n",
			verity_metadata.metadata_start);

	ret = sys_lseek(block_fd, verity_metadata.metadata_start, 0);
	if (ret != verity_metadata.metadata_start) {
		pr_init_err("Unable to seek to metadata start\n");
		goto error;
	}

	/* Read and verify magic number */
	ret = sys_read(block_fd, (unsigned char *)&parameter,
			sizeof(parameter));
	if (ret != sizeof(parameter)) {
		pr_init_err("Unable to read magic_number: %zu bytes\n",
			sizeof(parameter));
		goto error;
	}

	verity_metadata.magic_number = le32_to_cpu(parameter);

	if (is_unlocked() && verity_metadata.magic_number ==
	    VERITY_METADATA_MAGIC_DISABLE) {
		retval = VERITY_STATE_DISABLE;
		goto error;
	}

	if (verity_metadata.magic_number != VERITY_METADATA_MAGIC_NUMBER) {
		pr_init_err("Incorrect magic number\n");
		goto error;
	}

	/* Read and verify protocol version */
	ret = sys_read(block_fd, (unsigned char *)&parameter,
			sizeof(parameter));
	if (ret != sizeof(parameter)) {
		pr_init_err("Unable to read protocol version: %zu bytes\n",
			sizeof(parameter));
		goto error;
	}

	verity_metadata.protocol_version = le32_to_cpu(parameter);

	if (verity_metadata.protocol_version != 0) {
		pr_init_err("Verity protocol version mismatch\n");
		goto error;
	}

	/* Read signature of the table*/
	ret = sys_read(block_fd, (unsigned char *)verity_metadata.signature,
			RSANUMBYTES);
	if (ret != RSANUMBYTES) {
		pr_init_err("Unable to read signature: %d bytes err: %lld\n",
			RSANUMBYTES, ret);
		goto error;
	}

	/* Read table length and check to see if its less than
	 * VERITY_METADATA_SIZE
	 */
	ret = sys_read(block_fd, (unsigned char *)&parameter,
			sizeof(parameter));
	if (ret != sizeof(parameter)) {
		pr_init_err("Unable to read table length: %zu bytes err: %lld\n",
			sizeof(parameter), ret);
		goto error;
	}

	verity_metadata.table_length = le32_to_cpu(parameter);

	pr_init_info("magic_number:%u protocol_version:%d table_length:%u\n",
		verity_metadata.magic_number, verity_metadata.protocol_version,
		verity_metadata.table_length);

	if (verity_metadata.table_length == 0 ||
	    verity_metadata.table_length > (VERITY_METADATA_SIZE -
					VERITY_HEADER_SIZE))
		goto error;

	/* Allocate memory and read verity table */
	verity_metadata.verity_table =
				vmalloc(verity_metadata.table_length + 1);

	if (!verity_metadata.verity_table) {
		retval = -ENOMEM;
		goto error;
	}

	ret = sys_read(block_fd, verity_metadata.verity_table,
			verity_metadata.table_length);
	if (ret != verity_metadata.table_length) {
		pr_init_err("Unable to read verity_table: %u bytes err: %lld\n",
			verity_metadata.table_length, ret);
		goto error;
	}

	verity_metadata.verity_table[verity_metadata.table_length] = '\0';

	pr_init_debug("verity_table: %s\n",
		verity_metadata.verity_table);

	if (VERITY_DEBUG)
		msleep(2000);

	retval = 0;
error:
	sys_close(block_fd);

	return retval;
}

static int __init handle_error(int mode)
{
	if (mode == VERITY_MODE_RESTART) {
		pr_init_info("triggering restart");
		kernel_restart("dm-verity device corrupted");
	} else {
		pr_init_err("Mounting root with verity disabled");
	}

	return VERITY_STATE_DISABLE;
}

static struct dm_setup_verity verity_args __initdata;

static void __init setup_callback(bool err)
{
	int mode = verity_mode();

	if (err)
		handle_error(mode);

	vfree(verity_metadata.verity_table);
	vfree(verity_args.target->params);
	vfree(verity_args.target->type);
	vfree(verity_args.target);
}

static int find_bits(u64 number)
{
	int i = 0;

	while (number > 0) {
		number = number >> 1;
		i++;
	}
	return i;
}

static struct dm_setup_verity * __init verity_setup_drive(int mode)
{
	int ret = 0;
	char *arg, *verity_table_args[VERITY_TABLE_ARGS], *table_ptr;
	int i = 0, arg_len;
	u64 data_sectors, data_block_size;
	static const char verity[] __initconst = "verity";
	static const char system[] __initconst = "system";
	static const char none[] __initconst = "none";
	struct dm_setup_target *target;
	dev_t dev;

	if (VERITY_DEBUG)
		msleep(10000);

	if (verity_create_dev(dm_verity_setup_args.device_name) < 0) {
		pr_init_err("Failed creating root device\n");
		ret = handle_error(mode);
		goto err;
	}

	/*
	 * if device state unlocked and MAGIC is disabled,
	 * do not replace root, continue mounting as
	 * without dm-verity for root partition.
	 */
	ret = extract_metadata();
	if (ret == VERITY_STATE_DISABLE) {
		pr_init_err("Verity disabled! Mounting root with verity disabled");
		goto err;
	}

	if (ret) {
		pr_init_err("error while extracting metadata");
		ret = handle_error(mode);
		if (verity_metadata.verity_table)
			goto err_verity_table;
		goto err;
	}

	if (verify_verity_signature()) {
		pr_init_err("Verity metadata signature verification failed\n");
		ret = handle_error(mode);
		goto err_verity_table;
	}

	pr_init_info("Verity metadata signature verified\n");

	arg_len = verity_metadata.table_length + 14; /* For DEV major minor */

	arg = vmalloc(arg_len);
	if (!arg) {
		ret = handle_error(mode);
		goto err_verity_table;
	}

	table_ptr = verity_metadata.verity_table;

	while (i < VERITY_TABLE_ARGS) {
		static const char delim[] __initconst = " ";

		verity_table_args[i] = strsep(&table_ptr, delim);
		if (verity_table_args[i] == NULL)
			break;
		i++;
	}

	if (table_ptr != NULL || i != VERITY_TABLE_ARGS) {
		pr_init_err("verity table not in the expected format\n");
		ret = handle_error(mode);
		goto err_arg;
	}

	if (kstrtoull(verity_table_args[5], 10, &data_sectors)) {
		pr_init_err("verity table not in the expected format\n");
		ret = handle_error(mode);
		goto err_arg;
	}

	if (kstrtoull(verity_table_args[3], 10, &data_block_size)) {
		pr_init_err("verity table not in the expected format\n");
		ret = handle_error(mode);
		goto err_arg;
	}

	if ((find_bits(data_sectors) + find_bits(data_block_size /
		SECTOR_SIZE)) <= 64)
		data_sectors = data_sectors * data_block_size / SECTOR_SIZE;
	else {
		pr_init_err("data_sectors to high\n");
		ret = handle_error(mode);
		goto err_arg;
	}

	verity_args.minor = 0;
	verity_args.ro = 1;
	strncpy(verity_args.name, system, DM_MAX_NAME - 1);
	verity_args.name[DM_MAX_NAME - 1] = '\0';
	strncpy(verity_args.uuid, none, DM_MAX_UUID - 1);
	verity_args.uuid[DM_MAX_UUID - 1] = '\0';
	verity_args.target_count = 1;
	verity_args.verity_setup_done = setup_callback;

	target = vmalloc(sizeof(*verity_args.target));
	if (!target) {
		ret = handle_error(mode);
		goto err_arg;
	}

	verity_args.target = target;
	target->begin = 0;
	target->length = data_sectors;
	target->next = NULL;
	target->type = vmalloc(sizeof(verity));
	if (!target->type) {
		ret = handle_error(mode);
		goto err_type;
	}

	strcpy(target->type, verity);
	dev = name_to_dev_t(dm_verity_setup_args.device_name);

	/* Build the argument string for dm_setup.
	 * Can be skipped once build system passes the data_sectors
	 * directy.
	 */
	{
		static const char fmt[] __initconst =
		"%s %u:%u %u:%u %s %s %s %s %s %s %s %d";
		scnprintf(arg, arg_len,
			fmt,
			verity_table_args[0],
			MAJOR(dev), MINOR(dev),
			MAJOR(dev), MINOR(dev),
			verity_table_args[3],
			verity_table_args[4],
			verity_table_args[5],
			verity_table_args[6],
			verity_table_args[7],
			verity_table_args[8],
			verity_table_args[9],
			mode);
	}

	target->params = arg;
	pr_init_debug("argument passed to verity: %s\n", arg);

	return &verity_args;
err_type:
	vfree(target);
err_arg:
	vfree(arg);
err_verity_table:
	vfree(verity_metadata.verity_table);
err:
	return ERR_PTR(-ENODEV);
}

struct dm_setup_verity * __init verity_run_setup(const char *rootdev)
{
	int mode = verity_mode();

	if (!verity_early_setup) {
		handle_error(mode);
		return ERR_PTR(-ENODEV);
	}

	pr_init_info("attempting early device configuration.\n");

	if ((strlen(rootdev) + 1) > sizeof(dm_verity_setup_args.device_name)) {
		pr_init_err("rootdev name too long.");
		handle_error(mode);
		return ERR_PTR(-ENODEV);
	}

	strlcpy(dm_verity_setup_args.device_name, rootdev,
		sizeof(dm_verity_setup_args.device_name));

	return verity_setup_drive(mode);
}
