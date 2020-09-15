/*
 * Copyright 1997-2005 Markus Hahn 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef __TRIPLEDES_H
#define __TRIPLEDES_H

#ifdef __cplusplus
extern "C" {
#endif

#include "cipherdef.h"


// some constants...
#define TRIPLEDES_KEYSIZE      21   // 3 * (8 - 1)
#define TRIPLEDES_BLOCKSIZE     8    
#define TRIPLEDES_CIPHERNAME    "Triple-DES"

// function interface

WORD32 TripleDES_GetCipherInfo(CIPHERINFOBLOCK*);

WORD32 TripleDES_SelfTest (void*);

WORD32 TripleDES_CreateWorkContext(void*, const WORD8*, WORD32, WORD32, void*,
                                   Cipher_RandomGenerator, const void*);

void TripleDES_ResetWorkContext(void*, WORD32, void*,
                                Cipher_RandomGenerator, const void*);

WORD32 TripleDES_DestroyWorkContext (void*);

void TripleDES_EncryptBuffer(void*, const void*, void*, WORD32);

void TripleDES_DecryptBuffer(void*, const void*, void*, WORD32, const void*);


#ifdef __cplusplus
}
#endif


#endif











