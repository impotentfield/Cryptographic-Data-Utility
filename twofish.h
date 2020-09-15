#ifndef __TWOFISH_H
#define __TWOFISH_H


#ifdef __cplusplus
extern "C" {
#endif

#include "cipherdef.h"

#define TWOFISH_KEYSIZE         32
#define TWOFISH_BLOCKSIZE       16
#define TWOFISH_CIPHERNAME      "Twofish"

WORD32 Twofish_GetCipherInfo(CIPHERINFOBLOCK*);

WORD32 Twofish_SelfTest (void* pTestContext);

WORD32 Twofish_CreateWorkContext(void*, const WORD8*, WORD32, WORD32, void*,
                                 Cipher_RandomGenerator, const void*);

void Twofish_ResetWorkContext(void*, WORD32, void*,
                              Cipher_RandomGenerator, const void*);

WORD32 Twofish_DestroyWorkContext (void*);

void Twofish_EncryptBuffer(void*, const void*, void*, WORD32);

void Twofish_DecryptBuffer(void*, const void*, void*, WORD32, const void*);

int cs_twofish();

#ifdef __cplusplus
}
#endif

#endif
