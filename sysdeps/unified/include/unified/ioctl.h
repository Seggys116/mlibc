#ifndef _ASM_IOCTL_H
#define _ASM_IOCTL_H

#include <stdint.h>

/* TTY ioctls */
#define TIOCGWINSZ  0x5413
#define TIOCSPTLCK 0x40045431
#define TIOCGPTN   0x40045430

/* File descriptor ioctls */
#define FIOCLEX    0x6601
#define FIONCLEX   0x6602

#endif
