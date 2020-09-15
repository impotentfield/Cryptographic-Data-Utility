
/*
 * defines basic primitive data types to avoid system independencies
 */

#ifndef __BASICTYPES_H
#define __BASICTYPES_H

#define CRYPTPAK_API

typedef unsigned char      WORD8;
typedef unsigned short     WORD16;
typedef unsigned int       WORD32;
typedef unsigned long long WORD64;

#define u8 WORD8
#define u16 WORD16
#define u32 WORD32

typedef unsigned char      BYTEBOOL;
typedef unsigned short     UNICHAR;

#define BOOL_FALSE  0
#define BOOL_TRUE   1

// some nice macros
#define MAKE_WORD64(left, right) ((((WORD64)(left)) << 32) | (WORD64)(right))
#define WORD64_LO(value) ((WORD32)(value & 0xffffffff))
#define WORD64_HI(value) ((WORD32)(value >> 32))

#endif

