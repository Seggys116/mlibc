#ifndef _UNIFIED_IOCTL_H
#define _UNIFIED_IOCTL_H

/* TTY ioctls */
#define TIOCGWINSZ  0x5413
#define TIOCSPTLCK 0x40045431
#define TIOCGPTN   0x40045430

/* File descriptor ioctls */
#define FIOCLEX    0x6601
#define FIONCLEX   0x6602

/* Terminal IOCTLs */
#define TCGETS     0x5401
#define TCSETS     0x5402
#define TCSETSW    0x5403
#define TCSETSF    0x5404

#endif
