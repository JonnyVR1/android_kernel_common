/*
 * Ioctl command table
 *
 * SELinux must keep a mapping of ioctl commands to labels/SIDs.  This
 * mapping is maintained as part of the normal policy but a fast cache is
 * needed to reduce the lookup overhead.
 *
 * Author: Jeff Vander Stoep <jeffv@google.com>
 *
 */


#ifndef _SELINUX_IOCTLCMD_H
#define _SELINUX_IOCTLCMD_H

int sel_ioctlcmd_sid(unsigned int cmd, u32 *sid);

#endif
