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


#ifndef _CAST_H
#define _CAST_H


#ifdef __cplusplus
extern "C" {
#endif

#include "cipherdef.h"


// some constants...
#define CAST_CIPHERNAME   "CAST"


// function interface

WORD32 CAST_GetCipherInfo(CIPHERINFOBLOCK*);

WORD32 CAST_SelfTest (void*);

WORD32 CAST_CreateWorkContext(void*, const WORD8*, WORD32, WORD32, void*,
                              Cipher_RandomGenerator, const void*);

void CAST_ResetWorkContext(void*, WORD32, void*,
                           Cipher_RandomGenerator, const void*);

WORD32 CAST_DestroyWorkContext (void*);

void CAST_EncryptBuffer(void*, const void*, void*, WORD32);

void CAST_DecryptBuffer(void*, const void*, void*, WORD32, const void*);


#ifdef __cplusplus
}
#endif



#endif       /* ifndef _CAST_H_ */
