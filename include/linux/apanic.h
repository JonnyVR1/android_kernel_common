#ifndef _LINUX_APANIC_H
#define _LINUX_APANIC_H

extern int apanic_dev_read(unsigned int addr, size_t *retlen, void *buf);
extern void apanic_dev_erase(void);
extern int apanic_dev_write(unsigned int to, const u_char *buf);

extern int apanic_register_device(int regunreg, unsigned int xfersize);

extern void apanic_sdhci_check_partition(char *name,
					 unsigned long startbyte,
					 unsigned long sizebytes,
					 struct device *blkdev);

extern void apanic_sdhci_register_device(char *, void *);

#endif /* _LINUX_APANIC_H */
