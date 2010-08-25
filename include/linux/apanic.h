#ifndef _LINUX_APANIC_H
#define _LINUX_APANIC_H

extern int apanic_dev_read(unsigned int addr, size_t *retlen, void *buf);
extern void apanic_dev_erase(void);
extern int apanic_dev_write(unsigned int to, const u_char *buf);

extern int apanic_register_device(int regunreg, unsigned int xfersize);



#endif /* _LINUX_APANIC_H */
