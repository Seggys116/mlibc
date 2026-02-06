#ifndef _UNIFIED_IOCTL_H
#define _UNIFIED_IOCTL_H

/* TTY ioctls */
#define TIOCGWINSZ  0x5413
#define TIOCGPTN   0x80045430  /* Get Pty Number (_IOR('T', 0x30, unsigned int)) */
#define TIOCSPTLCK 0x40045431  /* Lock/unlock Pty (_IOW('T', 0x31, int)) */
#define TIOCGPTLCK 0x80045439  /* Get PTY lock state (_IOR('T', 0x39, int)) */

/* File descriptor ioctls */
#define FIOCLEX    0x6601
#define FIONCLEX   0x6602

/* Terminal IOCTLs */
#define TCGETS     0x5401
#define TCSETS     0x5402
#define TCSETSW    0x5403
#define TCSETSF    0x5404

#endif
