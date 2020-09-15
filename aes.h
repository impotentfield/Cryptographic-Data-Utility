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


#ifndef __AES_H
#define __AES_H

#ifdef __cplusplus
extern "C" {
#endif

#include "cipherdef.h"

#define AES_KEYSIZE    32
#define AES_BLOCKSIZE  16
#define AES_CIPHERNAME "AES"

WORD32 AES_GetCipherInfo(CIPHERINFOBLOCK*);

WORD32 AES_SelfTest(void*);

WORD32 AES_CreateWorkContext(void*,
							 const WORD8*,
							 WORD32,
							 WORD32,
							 void*,
							 Cipher_RandomGenerator,
							 const void*);

void AES_ResetWorkContext(void*,
						  WORD32,
						  void*,
						  Cipher_RandomGenerator,
						  const void*);

WORD32 AES_DestroyWorkContext(void*);

void AES_EncryptBuffer(void*,
					   const void*,
					   void*,
					   WORD32);

void AES_DecryptBuffer(void*,
					   const void*,
					   void*,
					   WORD32,
					   const void*);

int cs_aes();

#ifdef __cplusplus
}
#endif

#endif
