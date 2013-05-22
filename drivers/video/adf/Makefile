ccflags-y := -Idrivers/staging/android -Idrivers/staging/android/sync

CFLAGS_adf.o := -I$(src)

obj-$(CONFIG_ADF) += adf.o \
	adf_client.o \
	adf_fops.o \
	adf_sysfs.o

obj-$(CONFIG_COMPAT) += adf_fops32.o
