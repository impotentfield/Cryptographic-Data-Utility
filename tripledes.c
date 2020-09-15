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


#include "tripledes.h"
#include "ciphervar.h"


// internal constants
#define KEYSETUP_ENCRYPTION     0
#define KEYSETUP_DECRYPTION     1

// triple-DES context
typedef struct {

  // key context #1 (1st encryption)
  WORD32 k1[32];
  // key context #2 (decryption)
  WORD32 k2[32];
  // key context #3 (2nd encryption)
  WORD32 k3[32];

  // the CBC IV
  WORD8 cbciv[TRIPLEDES_BLOCKSIZE];

  // legacy support switch
  BYTEBOOL blLegacy;
} 
TRIPLEDESCTX;


// prototypes of the support routines
void _expandPureDESKey(const WORD8*, WORD8*);
void _keysetup(WORD8*, int, WORD32*);
void _processBlock(WORD8*, WORD8*, WORD32*);
void _blkcpy(WORD8*, WORD8*);
void _blkcpy_r(WORD8*, WORD8*);

int cs_tripledes()
{
	return sizeof(TRIPLEDESCTX);
}

WORD32 TripleDES_GetCipherInfo
(CIPHERINFOBLOCK* pInfo) 
{
	WORD8* pSrc;
	WORD8* pDst;
	CIPHERINFOBLOCK tempinfo;
	WORD32 lI;

	// prepare the information context
	tempinfo.lSizeOf = pInfo->lSizeOf;
	tempinfo.lBlockSize = TRIPLEDES_BLOCKSIZE;
	tempinfo.lKeySize = TRIPLEDES_KEYSIZE; 
	tempinfo.blOwnHasher = BOOL_FALSE;
	tempinfo.lInitDataSize = TRIPLEDES_BLOCKSIZE;
	tempinfo.lContextSize = sizeof(TRIPLEDESCTX);
	tempinfo.bCipherIs = CIPHER_IS_BLOCKLINK;

	// copy as many bytes of the information block as possible
	pSrc = (WORD8*) &tempinfo;
	pDst = (WORD8*) pInfo;
	for (lI = 0; lI < tempinfo.lSizeOf; lI++)
		*pDst++ = *pSrc++;

	return CIPHER_ERROR_NOERROR;
}



WORD32 TripleDES_SelfTest 
(void* pTestContext) 
{
	// test the cipher for correct encrypting and decrypting
	// (we test only a single DES stage with the original validation sets)

	static WORD8 refkey[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
	static WORD8 plainBlock[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xe7 };
	static WORD8 cipherBlock[8] = { 0xc9, 0x57, 0x44, 0x25, 0x6a, 0x5e, 0xd3, 0x1d };
	WORD8 workBlock[8];
	WORD32 k[32];
	int nI;

	// encrypt the test block
	_keysetup(refkey, KEYSETUP_ENCRYPTION, k);
	_processBlock(plainBlock, workBlock, k);

	// equal ciphertexts?
	for (nI = 0; nI < 8; nI++)
		if (workBlock[nI] != cipherBlock[nI]) return CIPHER_ERROR_INVALID;

	// decrypt the test block
	_keysetup(refkey, KEYSETUP_DECRYPTION, k);
	_processBlock(workBlock, workBlock, k);

	// equal plaintexts?
	for (nI = 0; nI < 8; nI++) 
	{
		if (plainBlock[nI] != workBlock[nI]) return CIPHER_ERROR_INVALID;
	}
	return CIPHER_ERROR_NOERROR;
}


#define CIPHER_GETMODE(lmode) (lmode)

WORD32 TripleDES_CreateWorkContext
(void* pContext,
 const WORD8* pKey,
 WORD32 lKeyLen,
 WORD32 lMode,
 void* pInitData,
 Cipher_RandomGenerator GetRndBytes,
 const void* pRndGenData) 
{
	int nI;
	WORD8* pbInit;
	WORD8 deskey1[8];
	WORD8 deskey2[8];
	WORD8 deskey3[8];
	TRIPLEDESCTX* pCtx;

	pCtx = (TRIPLEDESCTX*) pContext;
	pCtx->blLegacy = 0;//(CIPHER_GETFLAGS(lMode) & CIPHER_MODE_FLAG_LEGACY) ? BOOL_TRUE : BOOL_FALSE;

	// create three DES keys from the "pure" key, ignoring the parity
	_expandPureDESKey(pKey, deskey1);
	_expandPureDESKey(pKey + 7, deskey2);
	_expandPureDESKey(pKey + 14, deskey3);

	// run the key setups
	if (CIPHER_GETMODE(lMode) == CIPHER_MODE_ENCRYPT) 
	{
		_keysetup(deskey1, KEYSETUP_ENCRYPTION, pCtx->k1);
		_keysetup(deskey2, KEYSETUP_DECRYPTION, pCtx->k2);
		_keysetup(deskey3, KEYSETUP_ENCRYPTION, pCtx->k3);
	}
	else 
	{
		_keysetup(deskey1, KEYSETUP_DECRYPTION, pCtx->k1);
		_keysetup(deskey2, KEYSETUP_ENCRYPTION, pCtx->k2);
		_keysetup(deskey3, KEYSETUP_DECRYPTION, pCtx->k3);
	}

	// delete the DES keys
	for (nI = 0; nI < 8; nI++) 
	{
		deskey1[nI] = 0;
		deskey2[nI] = 0;
		deskey3[nI] = 0;
	}

	// for encryption create a CBC IV
if ( cipher_block_mode == CIPHER_MODE_CBC ) {
	pbInit = (WORD8*) pInitData;
	if (lMode == CIPHER_MODE_ENCRYPT)
	{
		GetRndBytes(pbInit, TRIPLEDES_BLOCKSIZE, pRndGenData);
	}

	if (pCtx->blLegacy)
	{
		// the old code stored everything completely reversed
		_blkcpy_r(pbInit, pCtx->cbciv);
	}
	else
	{
		_blkcpy(pbInit, pCtx->cbciv);
	}
}
	// FIXME: weak keys in triple-DES?
	return CIPHER_ERROR_NOERROR;
}


void TripleDES_ResetWorkContext
(void* pContext,
 WORD32 lMode,
 void* pInitData,
 Cipher_RandomGenerator GetRndBytes,
 const void* pRndGenData) 
{
	TRIPLEDESCTX* pCtx = (TRIPLEDESCTX*) pContext;

	// just reset the CBC IV 
	WORD8* pbInit = (WORD8*) pInitData;
	if (CIPHER_GETMODE(lMode) == CIPHER_MODE_ENCRYPT)
		GetRndBytes(pbInit, TRIPLEDES_BLOCKSIZE, pRndGenData);

	if (pCtx->blLegacy)
	{
		_blkcpy_r(pbInit, pCtx->cbciv);
	}
	else
	{
		_blkcpy(pbInit, pCtx->cbciv);
	}
}



WORD32 TripleDES_DestroyWorkContext
(void* pContext) 
{
	// clear the context
	int nI;
	WORD8* pClearIt = (WORD8*) pContext;
	for (nI = 0; nI < sizeof(TRIPLEDESCTX); nI++) 
		pClearIt[nI] = 0x00;
	return CIPHER_ERROR_NOERROR;
}



void TripleDES_EncryptBuffer
(void* pContext,
 const void* pSource,
 void* pTarget,
 WORD32 lNumOfBytes) 
{
	WORD32 lI, lJ;
	WORD8* pbIn = (WORD8*) pSource;
	WORD8* pbOut = (WORD8*) pTarget;
	TRIPLEDESCTX* pCtx = (TRIPLEDESCTX*) pContext;

	lNumOfBytes &= ~(TRIPLEDES_BLOCKSIZE - 1);

	// work through all blocks... 
	for (lI = 0; lI < lNumOfBytes; lI += TRIPLEDES_BLOCKSIZE) 
	{
		// copy and chain the recent block 
if ( cipher_block_mode == CIPHER_MODE_CBC ) {
		if (pCtx->blLegacy)
		{
			// (we have to bring back the CBC IV into 64bit little endian)
			for (lJ = 0; lJ < TRIPLEDES_BLOCKSIZE; lJ++)
				pbOut[lI + lJ] = pbIn[lI + lJ] ^ pCtx->cbciv[(TRIPLEDES_BLOCKSIZE - 1) - lJ];
		}
		else
		{
			for (lJ = 0; lJ < TRIPLEDES_BLOCKSIZE; lJ++)
				pbOut[lI + lJ] = pbIn[lI + lJ] ^ pCtx->cbciv[lJ];
		}
} else {
			for (lJ = 0; lJ < TRIPLEDES_BLOCKSIZE; lJ++)
				pbOut[lI + lJ] = pbIn[lI + lJ];
}

		// encrypt the block
		_processBlock(&pbOut[lI], &pbOut[lI], pCtx->k1);
		_processBlock(&pbOut[lI], &pbOut[lI], pCtx->k2);
		_processBlock(&pbOut[lI], &pbOut[lI], pCtx->k3);

		// set the new CBC IV (same as above)
if ( cipher_block_mode == CIPHER_MODE_CBC ) {
		if (pCtx->blLegacy)
		{
			_blkcpy_r(&pbOut[lI], pCtx->cbciv);
		}
		else
		{
			_blkcpy(&pbOut[lI], pCtx->cbciv);
		}
	}
}

}



void TripleDES_DecryptBuffer
(void* pContext,
 const void* pSource,
 void* pTarget, 
 WORD32 lNumOfBytes,
 const void* pPreviousBlock) 
{
	WORD32 lI, lJ;
	WORD8 saveiv[TRIPLEDES_BLOCKSIZE];
	WORD8* pbIn = (WORD8*) pSource;
	WORD8* pbOut = (WORD8*) pTarget;
	WORD8* pbPrev;
	TRIPLEDESCTX* pCtx = (TRIPLEDESCTX*) pContext;

	lNumOfBytes &= ~(TRIPLEDES_BLOCKSIZE - 1);

if ( cipher_block_mode == CIPHER_MODE_CBC ) {
	// load a new CBC IV, if necessary 
	if (pPreviousBlock != CIPHER_NULL)  
	{
		pbPrev = (WORD8*)pPreviousBlock;
		if (pCtx->blLegacy)
		{
			_blkcpy_r(pbPrev, pCtx->cbciv);
		}
		else
		{
			_blkcpy(pbPrev, pCtx->cbciv);
		}
	}
}
	// work through all blocks... 
	for (lI = 0; lI < lNumOfBytes; lI += 8) 
	{
if ( cipher_block_mode == CIPHER_MODE_CBC )
		// save the recent CBC IV (don't care for the layout right now)
		_blkcpy(&pbIn[lI], saveiv);

		// decrypt the block 
		_processBlock(&pbIn [lI], &pbOut[lI], pCtx->k3);
		_processBlock(&pbOut[lI], &pbOut[lI], pCtx->k2);
		_processBlock(&pbOut[lI], &pbOut[lI], pCtx->k1);

if ( cipher_block_mode == CIPHER_MODE_CBC ) {
		// dechain the recent block
		if (pCtx->blLegacy)
		{
			// same as above: bring back the IV into the old format
			for (lJ = 0; lJ < TRIPLEDES_BLOCKSIZE; lJ++)
				pbOut[lI + lJ] ^= pCtx->cbciv[(TRIPLEDES_BLOCKSIZE - 1) - lJ];
		}
		else
		{
			for (lJ = 0; lJ < TRIPLEDES_BLOCKSIZE; lJ++)
				pbOut[lI + lJ] ^= pCtx->cbciv[lJ];
		}

		// set the new CBC IV (normalized)
		if (pCtx->blLegacy)
		{
			_blkcpy_r(saveiv, pCtx->cbciv);
		}
		else
		{
			_blkcpy(saveiv, pCtx->cbciv);
		}
}
	}
}

//////////////////////////////////////////////////////////////////////////////


// support routines implementation...


// constant stuff...

static WORD8 pc1[56] = 
{
	56, 48, 40, 32, 24, 16,  8,  0, 57, 49, 41, 33, 25, 17,
	9,  1, 58, 50, 42, 34, 26, 18, 10,  2, 59, 51, 43, 35,
	62, 54, 46, 38, 30, 22, 14,  6, 61, 53, 45, 37, 29, 21,
	13,  5, 60, 52, 44, 36, 28, 20, 12,  4, 27, 19, 11,  3 
};

static WORD8 totrot[16] = 
{
	1,2,4,6,8,10,12,14,15,17,19,21,23,25,27,28 
};

static WORD8 pc2[48] = 
{
	13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
	22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
	40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
	43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31 
};


static WORD16 bytebit[8] = 
{
	0200, 0100, 040, 020, 010, 04, 02, 01 
};

static WORD32 bigbyte[24] = 
{
	0x800000L,  0x400000L,  0x200000L,  0x100000L,
	0x80000L,   0x40000L,   0x20000L,   0x10000L,
	0x8000L,    0x4000L,    0x2000L,    0x1000L,
	0x800L,     0x400L,     0x200L,     0x100L,
	0x80L,      0x40L,      0x20L,      0x10L,
	0x8L,       0x4L,       0x2L,       0x1L    
};

static unsigned long SP1[64] = 
{
	0x01010400L, 0x00000000L, 0x00010000L, 0x01010404L,
	0x01010004L, 0x00010404L, 0x00000004L, 0x00010000L,
	0x00000400L, 0x01010400L, 0x01010404L, 0x00000400L,
	0x01000404L, 0x01010004L, 0x01000000L, 0x00000004L,
	0x00000404L, 0x01000400L, 0x01000400L, 0x00010400L,
	0x00010400L, 0x01010000L, 0x01010000L, 0x01000404L,
	0x00010004L, 0x01000004L, 0x01000004L, 0x00010004L,
	0x00000000L, 0x00000404L, 0x00010404L, 0x01000000L,
	0x00010000L, 0x01010404L, 0x00000004L, 0x01010000L,
	0x01010400L, 0x01000000L, 0x01000000L, 0x00000400L,
	0x01010004L, 0x00010000L, 0x00010400L, 0x01000004L,
	0x00000400L, 0x00000004L, 0x01000404L, 0x00010404L,
	0x01010404L, 0x00010004L, 0x01010000L, 0x01000404L,
	0x01000004L, 0x00000404L, 0x00010404L, 0x01010400L,
	0x00000404L, 0x01000400L, 0x01000400L, 0x00000000L,
	0x00010004L, 0x00010400L, 0x00000000L, 0x01010004L 
};

static unsigned long SP2[64] = 
{
	0x80108020L, 0x80008000L, 0x00008000L, 0x00108020L,
	0x00100000L, 0x00000020L, 0x80100020L, 0x80008020L,
	0x80000020L, 0x80108020L, 0x80108000L, 0x80000000L,
	0x80008000L, 0x00100000L, 0x00000020L, 0x80100020L,
	0x00108000L, 0x00100020L, 0x80008020L, 0x00000000L,
	0x80000000L, 0x00008000L, 0x00108020L, 0x80100000L,
	0x00100020L, 0x80000020L, 0x00000000L, 0x00108000L,
	0x00008020L, 0x80108000L, 0x80100000L, 0x00008020L,
	0x00000000L, 0x00108020L, 0x80100020L, 0x00100000L,
	0x80008020L, 0x80100000L, 0x80108000L, 0x00008000L,
	0x80100000L, 0x80008000L, 0x00000020L, 0x80108020L,
	0x00108020L, 0x00000020L, 0x00008000L, 0x80000000L,
	0x00008020L, 0x80108000L, 0x00100000L, 0x80000020L,
	0x00100020L, 0x80008020L, 0x80000020L, 0x00100020L,
	0x00108000L, 0x00000000L, 0x80008000L, 0x00008020L,
	0x80000000L, 0x80100020L, 0x80108020L, 0x00108000L 
};

static unsigned long SP3[64] = 
{
	0x00000208L, 0x08020200L, 0x00000000L, 0x08020008L,
	0x08000200L, 0x00000000L, 0x00020208L, 0x08000200L,
	0x00020008L, 0x08000008L, 0x08000008L, 0x00020000L,
	0x08020208L, 0x00020008L, 0x08020000L, 0x00000208L,
	0x08000000L, 0x00000008L, 0x08020200L, 0x00000200L,
	0x00020200L, 0x08020000L, 0x08020008L, 0x00020208L,
	0x08000208L, 0x00020200L, 0x00020000L, 0x08000208L,
	0x00000008L, 0x08020208L, 0x00000200L, 0x08000000L,
	0x08020200L, 0x08000000L, 0x00020008L, 0x00000208L,
	0x00020000L, 0x08020200L, 0x08000200L, 0x00000000L,
	0x00000200L, 0x00020008L, 0x08020208L, 0x08000200L,
	0x08000008L, 0x00000200L, 0x00000000L, 0x08020008L,
	0x08000208L, 0x00020000L, 0x08000000L, 0x08020208L,
	0x00000008L, 0x00020208L, 0x00020200L, 0x08000008L,
	0x08020000L, 0x08000208L, 0x00000208L, 0x08020000L,
	0x00020208L, 0x00000008L, 0x08020008L, 0x00020200L 
};

static unsigned long SP4[64] = 
{
	0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
	0x00802080L, 0x00800081L, 0x00800001L, 0x00002001L,
	0x00000000L, 0x00802000L, 0x00802000L, 0x00802081L,
	0x00000081L, 0x00000000L, 0x00800080L, 0x00800001L,
	0x00000001L, 0x00002000L, 0x00800000L, 0x00802001L,
	0x00000080L, 0x00800000L, 0x00002001L, 0x00002080L,
	0x00800081L, 0x00000001L, 0x00002080L, 0x00800080L,
	0x00002000L, 0x00802080L, 0x00802081L, 0x00000081L,
	0x00800080L, 0x00800001L, 0x00802000L, 0x00802081L,
	0x00000081L, 0x00000000L, 0x00000000L, 0x00802000L,
	0x00002080L, 0x00800080L, 0x00800081L, 0x00000001L,
	0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
	0x00802081L, 0x00000081L, 0x00000001L, 0x00002000L,
	0x00800001L, 0x00002001L, 0x00802080L, 0x00800081L,
	0x00002001L, 0x00002080L, 0x00800000L, 0x00802001L,
	0x00000080L, 0x00800000L, 0x00002000L, 0x00802080L 
};

static unsigned long SP5[64] = 
{
	0x00000100L, 0x02080100L, 0x02080000L, 0x42000100L,
	0x00080000L, 0x00000100L, 0x40000000L, 0x02080000L,
	0x40080100L, 0x00080000L, 0x02000100L, 0x40080100L,
	0x42000100L, 0x42080000L, 0x00080100L, 0x40000000L,
	0x02000000L, 0x40080000L, 0x40080000L, 0x00000000L,
	0x40000100L, 0x42080100L, 0x42080100L, 0x02000100L,
	0x42080000L, 0x40000100L, 0x00000000L, 0x42000000L,
	0x02080100L, 0x02000000L, 0x42000000L, 0x00080100L,
	0x00080000L, 0x42000100L, 0x00000100L, 0x02000000L,
	0x40000000L, 0x02080000L, 0x42000100L, 0x40080100L,
	0x02000100L, 0x40000000L, 0x42080000L, 0x02080100L,
	0x40080100L, 0x00000100L, 0x02000000L, 0x42080000L,
	0x42080100L, 0x00080100L, 0x42000000L, 0x42080100L,
	0x02080000L, 0x00000000L, 0x40080000L, 0x42000000L,
	0x00080100L, 0x02000100L, 0x40000100L, 0x00080000L,
	0x00000000L, 0x40080000L, 0x02080100L, 0x40000100L 
};

static unsigned long SP6[64] = 
{
	0x20000010L, 0x20400000L, 0x00004000L, 0x20404010L,
	0x20400000L, 0x00000010L, 0x20404010L, 0x00400000L,
	0x20004000L, 0x00404010L, 0x00400000L, 0x20000010L,
	0x00400010L, 0x20004000L, 0x20000000L, 0x00004010L,
	0x00000000L, 0x00400010L, 0x20004010L, 0x00004000L,
	0x00404000L, 0x20004010L, 0x00000010L, 0x20400010L,
	0x20400010L, 0x00000000L, 0x00404010L, 0x20404000L,
	0x00004010L, 0x00404000L, 0x20404000L, 0x20000000L,
	0x20004000L, 0x00000010L, 0x20400010L, 0x00404000L,
	0x20404010L, 0x00400000L, 0x00004010L, 0x20000010L,
	0x00400000L, 0x20004000L, 0x20000000L, 0x00004010L,
	0x20000010L, 0x20404010L, 0x00404000L, 0x20400000L,
	0x00404010L, 0x20404000L, 0x00000000L, 0x20400010L,
	0x00000010L, 0x00004000L, 0x20400000L, 0x00404010L,
	0x00004000L, 0x00400010L, 0x20004010L, 0x00000000L,
	0x20404000L, 0x20000000L, 0x00400010L, 0x20004010L 
};

static unsigned long SP7[64] = 
{
	0x00200000L, 0x04200002L, 0x04000802L, 0x00000000L,
	0x00000800L, 0x04000802L, 0x00200802L, 0x04200800L,
	0x04200802L, 0x00200000L, 0x00000000L, 0x04000002L,
	0x00000002L, 0x04000000L, 0x04200002L, 0x00000802L,
	0x04000800L, 0x00200802L, 0x00200002L, 0x04000800L,
	0x04000002L, 0x04200000L, 0x04200800L, 0x00200002L,
	0x04200000L, 0x00000800L, 0x00000802L, 0x04200802L,
	0x00200800L, 0x00000002L, 0x04000000L, 0x00200800L,
	0x04000000L, 0x00200800L, 0x00200000L, 0x04000802L,
	0x04000802L, 0x04200002L, 0x04200002L, 0x00000002L,
	0x00200002L, 0x04000000L, 0x04000800L, 0x00200000L,
	0x04200800L, 0x00000802L, 0x00200802L, 0x04200800L,
	0x00000802L, 0x04000002L, 0x04200802L, 0x04200000L,
	0x00200800L, 0x00000000L, 0x00000002L, 0x04200802L,
	0x00000000L, 0x00200802L, 0x04200000L, 0x00000800L,
	0x04000002L, 0x04000800L, 0x00000800L, 0x00200002L 
};

static unsigned long SP8[64] = 
{
	0x10001040L, 0x00001000L, 0x00040000L, 0x10041040L,
	0x10000000L, 0x10001040L, 0x00000040L, 0x10000000L,
	0x00040040L, 0x10040000L, 0x10041040L, 0x00041000L,
	0x10041000L, 0x00041040L, 0x00001000L, 0x00000040L,
	0x10040000L, 0x10000040L, 0x10001000L, 0x00001040L,
	0x00041000L, 0x00040040L, 0x10040040L, 0x10041000L,
	0x00001040L, 0x00000000L, 0x00000000L, 0x10040040L,
	0x10000040L, 0x10001000L, 0x00041040L, 0x00040000L,
	0x00041040L, 0x00040000L, 0x10041000L, 0x00001000L,
	0x00000040L, 0x10040040L, 0x00001000L, 0x00041040L,
	0x10001000L, 0x00000040L, 0x10000040L, 0x10040000L,
	0x10040040L, 0x10000000L, 0x00040000L, 0x10001040L,
	0x00000000L, 0x10041040L, 0x00040040L, 0x10000040L,
	0x10040000L, 0x10001000L, 0x10001040L, 0x00000000L,
	0x10041040L, 0x00041000L, 0x00041000L, 0x00001040L,
	0x00001040L, 0x00040040L, 0x10000000L, 0x10041000L 
};


// to setup a DES key
// -> (raw) 64 bits of key material
// -> setup method, see KEYSETUP_xxx constants
// -> pointer to work key
void _keysetup
(WORD8* key, 
 int nKeySetup, 
 WORD32* k) 
{
	register int nI, nJ, nL, nM, nN;
	WORD8 pc1m[56], pcr[56];
	WORD32 kn[32];
	WORD32* raw1;
	WORD32* raw0;
	WORD32* cook;


	// primary setup
	for (nJ = 0; nJ < 56; nJ++) 
	{
		nL = pc1[nJ];
		nM = nL & 07;
		pc1m[nJ] = (key[nL >> 3] & bytebit[nM]) ? 1 : 0;
	}
	for (nI = 0; nI < 16; nI++) 
	{
		if (nKeySetup == KEYSETUP_DECRYPTION) nM = (15 - nI) << 1;
		else nM = nI << 1;
		nN = nM + 1;
		kn[nM] = kn[nN] = 0;
		for (nJ = 0; nJ < 28; nJ++) 
		{
			nL = nJ + totrot[nI];
			if (nL < 28 ) pcr[nJ] = pc1m[nL];
			else pcr[nJ] = pc1m[nL - 28];
		}
		for (nJ = 28; nJ < 56; nJ++) 
		{
			nL = nJ + totrot[nI];
			if (nL < 56 ) pcr[nJ] = pc1m[nL];
			else pcr[nJ] = pc1m[nL - 28];
		}
		for (nJ = 0; nJ < 24; nJ++ ) 
		{
			if (pcr[pc2[nJ]])      kn[nM] |= bigbyte[nJ];
			if (pcr[pc2[nJ + 24]]) kn[nN] |= bigbyte[nJ];
		}
	}

	// cookey and storage
	raw1 = &kn[0];
	cook = k;
	for (nI = 0; nI < 16; nI++, raw1++ ) 
	{
		raw0 = raw1++;
		*cook    = (*raw0 & 0x00fc0000) << 6;
		*cook   |= (*raw0 & 0x00000fc0) << 10;
		*cook   |= (*raw1 & 0x00fc0000) >> 10;
		*cook++ |= (*raw1 & 0x00000fc0) >> 6;
		*cook    = (*raw0 & 0x0003f000) << 12;
		*cook   |= (*raw0 & 0x0000003f) << 16;
		*cook   |= (*raw1 & 0x0003f000) >> 4;
		*cook++ |= (*raw1 & 0x0000003f);
	}
}


// we believe in 100% pure DES
void scrunch(WORD8* outof, WORD32* into) 
{
	*into    = (WORD32)(*outof++) << 24;
	*into   |= (WORD32)(*outof++) << 16;
	*into   |= (WORD32)(*outof++) << 8;
	*into++ |= (WORD32)(*outof++);
	*into    = (WORD32)(*outof++) << 24;
	*into   |= (WORD32)(*outof++) << 16;
	*into   |= (WORD32)(*outof++) << 8;
	*into   |= (WORD32)(*outof);
}
void unscrunch(WORD32* outof, WORD8* into) 
{
	*into++ = (WORD8)(*outof >> 24);
	*into++ = (WORD8)(*outof >> 16);
	*into++ = (WORD8)(*outof >>  8);
	*into++ = (WORD8)(*outof++);
	*into++ = (WORD8)(*outof >> 24);
	*into++ = (WORD8)(*outof >> 16);
	*into++ = (WORD8)(*outof >>  8);
	*into   = (WORD8)(*outof);
}



// encrypts or decrypts a block of data
// -> input block (may be the same as the output block)
// -> output block
// -> pointer to work key
void _processBlock
(WORD8* inblock, 
 WORD8* outblock, 
 WORD32* keys) 
{
	register WORD32 lF, lWork, lRight, lLeft;
	register int nRound;
	WORD32 transblock[2];

	// get the block
	scrunch(inblock, transblock);
	lLeft = transblock[0];
	lRight = transblock[1];

	// init. permutation
	lWork = ((lLeft >> 4) ^ lRight) & 0x0f0f0f0fL;
	lRight ^= lWork;
	lLeft ^= (lWork << 4);
	lWork = ((lLeft >> 16) ^ lRight) & 0x0000ffffL;
	lRight ^= lWork;
	lLeft ^= (lWork << 16);
	lWork = ((lRight >> 2) ^ lLeft) & 0x33333333L;
	lLeft ^= lWork;
	lRight ^= (lWork << 2);
	lWork = ((lRight >> 8) ^ lLeft) & 0x00ff00ffL;
	lLeft ^= lWork;
	lRight ^= (lWork << 8);
	lRight = ((lRight << 1) | ((lRight >> 31) & 1L)) & 0xffffffffL;
	lWork = (lLeft ^ lRight) & 0xaaaaaaaaL;
	lLeft ^= lWork;
	lRight ^= lWork;
	lLeft = ((lLeft << 1) | ((lLeft >> 31) & 1L)) & 0xffffffffL;

	// en- or decryption rounds
	for (nRound = 0; nRound < 8; nRound++ ) 
	{
		lWork  = (lRight << 28) | (lRight >> 4);
		lWork ^= *keys++;
		lF  = SP7[ lWork        & 0x3fL];
		lF |= SP5[(lWork >>  8) & 0x3fL];
		lF |= SP3[(lWork >> 16) & 0x3fL];
		lF |= SP1[(lWork >> 24) & 0x3fL];
		lWork  = lRight ^ *keys++;
		lF |= SP8[ lWork        & 0x3fL];
		lF |= SP6[(lWork >>  8) & 0x3fL];
		lF |= SP4[(lWork >> 16) & 0x3fL];
		lF |= SP2[(lWork >> 24) & 0x3fL];
		lLeft ^= lF;
		lWork  = (lLeft << 28) | (lLeft >> 4);
		lWork ^= *keys++;
		lF  = SP7[ lWork        & 0x3fL];
		lF |= SP5[(lWork >>  8) & 0x3fL];
		lF |= SP3[(lWork >> 16) & 0x3fL];
		lF |= SP1[(lWork >> 24) & 0x3fL];
		lWork  = lLeft ^ *keys++;
		lF |= SP8[ lWork        & 0x3fL];
		lF |= SP6[(lWork >>  8) & 0x3fL];
		lF |= SP4[(lWork >> 16) & 0x3fL];
		lF |= SP2[(lWork >> 24) & 0x3fL];
		lRight ^= lF;
	}


	// final permutation
	lRight = (lRight << 31) | (lRight >> 1);
	lWork = (lLeft ^ lRight) & 0xaaaaaaaaL;
	lLeft ^= lWork;
	lRight ^= lWork;
	lLeft = (lLeft << 31) | (lLeft >> 1);
	lWork = ((lLeft >> 8) ^ lRight) & 0x00ff00ffL;
	lRight ^= lWork;
	lLeft ^= (lWork << 8);
	lWork = ((lLeft >> 2) ^ lRight) & 0x33333333L;
	lRight ^= lWork;
	lLeft ^= (lWork << 2);
	lWork = ((lRight >> 16) ^ lLeft) & 0x0000ffffL;
	lLeft ^= lWork;
	lRight ^= (lWork << 16);
	lWork = ((lRight >> 4) ^ lLeft) & 0x0f0f0f0fL;
	lLeft ^= lWork;
	lRight ^= (lWork << 4);

	// set the block
	transblock[0] = lRight;
	transblock[1] = lLeft;
	unscrunch(transblock, outblock);
}




// expands a "pure" 7byte key to an 8 byte key,
// the parity bit is ignored an always set to zero
// -> pointer to pure key
// -> pointer where to write the expanded key
void _expandPureDESKey
(const WORD8* src, 
 WORD8* dest) 
{
	int nI, nJ, nC, nBitCounter;
	WORD8 bPureByte;
	WORD8 bBuild;

	// cycle through all bytes
	nBitCounter = 0;
	bBuild = 0;
	nC = 0;
	for (nI = 0; nI < 7; nI++) 
	{
		bPureByte = src[nI];
		for (nJ = 0; nJ < 8; nJ++) 
		{
			bBuild |= (bPureByte >> nJ) & 0x01;
			bBuild <<= 1;
			nBitCounter++;
			if (nBitCounter == 7) 
			{
				dest[nC++] = bBuild;
				bBuild = 0;
				nBitCounter = 0;
			}
		}
	}
}

void _blkcpy(WORD8* src, WORD8* dst)
{
	int nI;
	for (nI = 0; nI < TRIPLEDES_BLOCKSIZE; nI++)
		dst[nI]	= src[nI];
}

void _blkcpy_r(WORD8* src, WORD8* dst)
{
	int nI;
	for (nI = 0; nI < TRIPLEDES_BLOCKSIZE; nI++)
		dst[nI]	= src[(TRIPLEDES_BLOCKSIZE - 1) - nI];
}
