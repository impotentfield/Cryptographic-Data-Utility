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

#include "blowfish.h"

// include the boxes init. data
#include "blowfishboxes.h"
#include "ciphervar.h"

#define BYTES_TO_WORD32(b)															\
	(((WORD32)((b)[0]) << 24)           | (((WORD32)((b)[1]) << 16) & 0x00ff0000) |	\
	(((WORD32)((b)[2]) <<  8) & 0xff00) |  ((WORD32)((b)[3])        &       0xff))

#define BYTES_TO_WORD32_X86(b)														\
	(((WORD32)((b)[3]) << 24)           | (((WORD32)((b)[2]) << 16) & 0x00ff0000) |	\
	(((WORD32)((b)[1]) <<  8) & 0xff00) |  ((WORD32)((b)[0])        &       0xff))

#define WORD32_TO_BYTES(w, b)									\
	(b)[0] = (WORD8)((w) >> 24); (b)[1] = (WORD8)((w) >> 16);	\
	(b)[2] = (WORD8)((w) >>  8); (b)[3] = (WORD8) (w);

#define WORD32_TO_BYTES_X86(w, b)								\
	(b)[3] = (WORD8)((w) >> 24); (b)[2] = (WORD8)((w) >> 16);	\
	(b)[1] = (WORD8)((w) >>  8); (b)[0] = (WORD8) (w);

// Blowfish work context


typedef struct 
{
	// the boxes
	WORD32 boxes[BOXES_SIZE];

	// session CBC IV
	WORD32 lCBCLo;
	WORD32 lCBCHi;

	BYTEBOOL blLegacy;
} 
BLOWFISHCTX;



// prototypes of the support routines
void __KeySetup(BLOWFISHCTX*, const WORD8*, WORD32);
void _BlowfishEncipher(BLOWFISHCTX*, WORD32*, WORD32*);
void _BlowfishDecipher(BLOWFISHCTX*, WORD32*, WORD32*);
BYTEBOOL _isWeakKey(BLOWFISHCTX*);


// box access constants
#define PBOX_POS    0
#define SBOX1_POS   PBOX_SIZE
#define SBOX2_POS   (PBOX_SIZE + SBOX_SIZE)
#define SBOX3_POS   (PBOX_SIZE + 2 * SBOX_SIZE)
#define SBOX4_POS   (PBOX_SIZE + 3 * SBOX_SIZE)


int cs_blowfish()
{
	return sizeof(BLOWFISHCTX);
}

WORD32 Blowfish_GetCipherInfo
(CIPHERINFOBLOCK* pInfo) 
{
	WORD32 lI;
	WORD8* pSrc;
	WORD8* pDst;
	CIPHERINFOBLOCK tempinfo;

	// prepare the information context
	tempinfo.lSizeOf = pInfo->lSizeOf;
	tempinfo.lBlockSize = BLOWFISH_BLOCKSIZE;
	tempinfo.lKeySize = BLOWFISH_KEYSIZE; 
	tempinfo.blOwnHasher = BOOL_FALSE;
	tempinfo.lInitDataSize = BLOWFISH_BLOCKSIZE;
	tempinfo.lContextSize = sizeof(BLOWFISHCTX);
	tempinfo.bCipherIs = CIPHER_IS_BLOCKLINK;

	// copy as many bytes of the information block as possible
	pSrc = (WORD8*) &tempinfo;
	pDst = (WORD8*) pInfo;

	for (lI = 0; lI < tempinfo.lSizeOf; lI++)
		*pDst++ = *pSrc++;

	return CIPHER_ERROR_NOERROR;
}



WORD32 Blowfish_SelfTest 
(void* pTestContext) 
{
	// test the cipher for correct encryption and decryption
	BLOWFISHCTX* testCtx = (BLOWFISHCTX*) pTestContext;

	// test vector #1 (check for the signed bug)
	WORD8 testKey1[8] = { 0x1c, 0x58, 0x7f, 0x1c, 0x13, 0x92, 0x4f, 0xef };
	WORD32 tv_p1[2] = { 0x30553228, 0x6d6f295a };
	WORD32 tv_c1[2] = { 0x55cb3774, 0xd13ef201 };
	WORD32 tv_t1[2] = { 0x00000000, 0x00000000 };

	// test vector #2 (offical vector by Bruce Schneier)
	WORD8* testKey2 = (WORD8*) "Who is John Galt?";
	WORD32 tv_p2[2] = { 0xfedcba98, 0x76543210 };
	WORD32 tv_c2[2] = { 0xcc91732b, 0x8022f684 };
	WORD32 tv_t2[2] = { 0x00000000, 0x00000000 };

	// test vector #3 (from a newer release of Counterpane),
	// also test correct memory handling
	WORD8 testKey3[8] = { 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
	WORD32 tv_p3[2] = { 0x01234567, 0x89abcdef };	
	WORD32 tv_c3[2] = { 0x0aceab0f, 0xc6a0a28d };
	WORD32 tv_t3[2] = { 0x00000000, 0x00000000 };

	// (the legacy flag actually does not matter in this test)
	testCtx->blLegacy = BOOL_FALSE;

	// test pass #1
	__KeySetup(testCtx, testKey1, 8);
	_BlowfishEncipher(testCtx, tv_p1, tv_t1);
	if ((tv_c1[0] != tv_t1[0]) || (tv_c1[1] != tv_t1[1])) 
		return CIPHER_ERROR_INVALID;
	_BlowfishDecipher(testCtx, tv_t1, tv_t1);
	if ((tv_p1[0] != tv_t1[0]) || (tv_p1[1] != tv_t1[1]))
		return CIPHER_ERROR_INVALID;

	// test pass #2
	__KeySetup(testCtx, testKey2, 17);
	_BlowfishEncipher(testCtx, tv_p2, tv_t2);
	if ((tv_c2[0] != tv_t2[0]) || (tv_c2[1] != tv_t2[1]))
		return CIPHER_ERROR_INVALID;
	_BlowfishDecipher(testCtx, tv_t2, tv_t2);
	if ((tv_p2[0] != tv_t2[0]) || (tv_p2[1] != tv_t2[1])) 
		return CIPHER_ERROR_INVALID;

	// test pass #3 (make sure we are compatible to the standard since
	// we read out of the memory bytewise)
	__KeySetup(testCtx, testKey3, 8);
	_BlowfishEncipher(testCtx, tv_p3, tv_t3);
	if ((tv_c3[0] != tv_t3[0]) || (tv_c3[1] != tv_t3[1]))
		return CIPHER_ERROR_INVALID;
	_BlowfishDecipher(testCtx, tv_t3, tv_t3);
	if ((tv_p3[0] != tv_t3[0]) || (tv_p3[1] != tv_t3[1])) 
		return CIPHER_ERROR_INVALID;

	// all tests passed
	return CIPHER_ERROR_NOERROR;
}


#define CIPHER_GETMODE(lmode) (lmode)
WORD32 Blowfish_CreateWorkContext
(void* pContext,
 const WORD8* pKey,
 WORD32 lKeyLen,
 WORD32 lMode,
 void* pInitData,
 Cipher_RandomGenerator GetRndBytes,
 const void* pRndGenData) 
{
	BLOWFISHCTX* pCtx = (BLOWFISHCTX*) pContext;
	WORD8* pbInit;

	// legacy or standard?
	pCtx->blLegacy = 0;//(CIPHER_GETFLAGS(lMode) & CIPHER_MODE_FLAG_LEGACY) ? BOOL_TRUE : BOOL_FALSE;

	// do the key setup (we ignore the passed key length now)
	__KeySetup(pCtx, pKey, BLOWFISH_KEYSIZE);

if ( cipher_block_mode == CIPHER_MODE_CBC ) {
	// for encryption create a CBC IV
	pbInit = (WORD8*) pInitData;
	if (CIPHER_GETMODE(lMode) == CIPHER_MODE_ENCRYPT)
	{
		GetRndBytes(pbInit, BLOWFISH_BLOCKSIZE, pRndGenData);
	}

	// set the CBC IV
	if (pCtx->blLegacy)
	{
		pCtx->lCBCLo = BYTES_TO_WORD32_X86(pbInit);
		pCtx->lCBCHi = BYTES_TO_WORD32_X86(pbInit + 4);
	}
	else
	{
		pCtx->lCBCHi = BYTES_TO_WORD32(pbInit);
		pCtx->lCBCLo = BYTES_TO_WORD32(pbInit + 4);
	}
}
	// check for weak keys and quit
	return (_isWeakKey(pCtx) == BOOL_TRUE) ? CIPHER_ERROR_WEAKKEY : CIPHER_ERROR_NOERROR;
}


void Blowfish_ResetWorkContext
(void* pContext,
 WORD32 lMode,
 void* pInitData,
 Cipher_RandomGenerator GetRndBytes,
 const void* pRndGenData) 
{
	BLOWFISHCTX* pCtx = (BLOWFISHCTX*) pContext;

	// just reset the CBC IV 
	WORD8* pbInit = (WORD8*) pInitData;
	if (CIPHER_GETMODE(lMode) == CIPHER_MODE_ENCRYPT) 
		GetRndBytes(pbInit, 8, pRndGenData);

	if (pCtx->blLegacy)
	{
		pCtx->lCBCLo = BYTES_TO_WORD32_X86(pbInit);
		pCtx->lCBCHi = BYTES_TO_WORD32_X86(pbInit + 4);
	}
	else
	{
		pCtx->lCBCHi = BYTES_TO_WORD32(pbInit);
		pCtx->lCBCLo = BYTES_TO_WORD32(pbInit + 4);
	}
}



WORD32 Blowfish_DestroyWorkContext
(void* pContext) 
{
	// clear the context
	int nI;
	WORD8* clearIt = (WORD8*) pContext;
	for (nI = 0; nI < sizeof(BLOWFISHCTX); nI++) clearIt[nI] = 0x00;
	return CIPHER_ERROR_NOERROR;
}



void Blowfish_EncryptBuffer
(void* pContext,
 const void* pSource,
 void* pTarget,
 WORD32 lNumOfBytes) 
{
	WORD32 lI;
	WORD8* pbIn = (WORD8*) pSource;
	WORD8* pbOut = (WORD8*) pTarget;
	WORD32 blk[2];
	BLOWFISHCTX* pCtx = (BLOWFISHCTX*) pContext;

	// anything to encrypt?
	if (0 == (lNumOfBytes &= ~7)) return;

	// work through all blocks... 
	for (lI = 0; lI < lNumOfBytes; lI += 8) 
	{
		// get and chain the block
		if (pCtx->blLegacy)
		{
if ( cipher_block_mode == CIPHER_MODE_CBC ) {
			blk[0] = BYTES_TO_WORD32_X86(pbIn) ^ pCtx->lCBCLo;
			blk[1] = BYTES_TO_WORD32_X86(pbIn + 4) ^ pCtx->lCBCHi;
} else {
			blk[0] = BYTES_TO_WORD32_X86(pbIn);
			blk[1] = BYTES_TO_WORD32_X86(pbIn + 4);

}
		}
		else
		{
if ( cipher_block_mode == CIPHER_MODE_CBC ) {
			blk[0] = BYTES_TO_WORD32(pbIn)  ^ pCtx->lCBCHi;
			blk[1] = BYTES_TO_WORD32(pbIn + 4) ^ pCtx->lCBCLo;
} else {
			blk[0] = BYTES_TO_WORD32(pbIn);
			blk[1] = BYTES_TO_WORD32(pbIn + 4);
}
		}
		pbIn += 8;

		// encrypt the block
		_BlowfishEncipher(pCtx, blk, blk);

		// copy it back and set the new CBC IV
		if (pCtx->blLegacy)
		{
			WORD32_TO_BYTES_X86(blk[0], pbOut)
			WORD32_TO_BYTES_X86(blk[1], pbOut + 4)
if ( cipher_block_mode == CIPHER_MODE_CBC ) {
			pCtx->lCBCLo = blk[0];
			pCtx->lCBCHi = blk[1];
}
		}
		else
		{
			WORD32_TO_BYTES(blk[0], pbOut)
			WORD32_TO_BYTES(blk[1], pbOut + 4)
if ( cipher_block_mode == CIPHER_MODE_CBC ) {			
			pCtx->lCBCHi = blk[0];
			pCtx->lCBCLo = blk[1];
}
		}

		pbOut += 8;
	}
}


void Blowfish_DecryptBuffer
(void* pContext,
 const void* pSource,
 void* pTarget, 
 WORD32 lNumOfBytes,
 const void* pPreviousBlock) 
{
	WORD32 lI;
	WORD32 blk[2];
	WORD32 saveIV[2];
	WORD8* pbIn = (WORD8*) pSource;
	WORD8* pbOut = (WORD8*) pTarget;
	WORD8* pbPrev = (WORD8*) pPreviousBlock;
	BLOWFISHCTX* pCtx = (BLOWFISHCTX*) pContext;

	// anything to decrypt?
	if (0 == (lNumOfBytes &= ~7)) return;

if ( cipher_block_mode == CIPHER_MODE_CBC ) {
	// load a new CBC IV, if necessary 
	if (CIPHER_NULL != pbPrev)  
	{
		if (pCtx->blLegacy)
		{
			pCtx->lCBCLo = BYTES_TO_WORD32_X86(pbPrev);
			pCtx->lCBCHi = BYTES_TO_WORD32_X86(pbPrev + 4);
		}
		else
		{
			pCtx->lCBCHi = BYTES_TO_WORD32(pbPrev);
			pCtx->lCBCLo = BYTES_TO_WORD32(pbPrev + 4);
		}
	}
}
	// work through all blocks... 
	for (lI = 0; lI < lNumOfBytes; lI += 8) 
	{
		// load the current block
		if (pCtx->blLegacy)
		{
			blk[0] = BYTES_TO_WORD32_X86(pbIn);
			blk[1] = BYTES_TO_WORD32_X86(pbIn + 4);
		}
		else
		{
			blk[0] = BYTES_TO_WORD32(pbIn);
			blk[1] = BYTES_TO_WORD32(pbIn + 4);
		}
		pbIn += 8;

if ( cipher_block_mode == CIPHER_MODE_CBC ) {
		// save the recent CBC IV 
		saveIV[0] = blk[0];
		saveIV[1] = blk[1];
}
		// decrypt the block 
		_BlowfishDecipher(pCtx, blk, blk);

		// unchain, store back the recent block and set the new IV
		if (pCtx->blLegacy)
		{
if ( cipher_block_mode == CIPHER_MODE_CBC ) {
			blk[0] ^= pCtx->lCBCLo;
			blk[1] ^= pCtx->lCBCHi;
}			
			WORD32_TO_BYTES_X86(blk[0], pbOut)
			WORD32_TO_BYTES_X86(blk[1], pbOut + 4)

if ( cipher_block_mode == CIPHER_MODE_CBC ) {
			pCtx->lCBCLo = saveIV[0];
			pCtx->lCBCHi = saveIV[1];
}
		}
		else
		{
if ( cipher_block_mode == CIPHER_MODE_CBC ) {
			blk[0] ^= pCtx->lCBCHi;
			blk[1] ^= pCtx->lCBCLo;
}			
			WORD32_TO_BYTES(blk[0], pbOut)
			WORD32_TO_BYTES(blk[1], pbOut + 4)
if ( cipher_block_mode == CIPHER_MODE_CBC ) {
			pCtx->lCBCHi = saveIV[0];
			pCtx->lCBCLo = saveIV[1];
}
		}

		pbOut += 8;
	}
}


// support routines...


// to setup a key (was extracted for an easier selftest implementation)
void __KeySetup
(BLOWFISHCTX* pCtx,
 const WORD8* pKey,
 WORD32 lKeyLen) 
{ 
	int nI;
	int nJ;
	WORD32 lKeyPos = 0;
	WORD32 lBuf = 0;
	WORD32 zerostr[2];

	// copy the init. data to the context
	for (nI = 0; nI < BOXES_SIZE; nI++) pCtx->boxes[nI] = boxes_init[nI];

	// we accept zero keys 
	if (lKeyLen == 0) return;

	// xor the key over the p-boxes, warp around
	for (nI = 0; nI < PBOX_SIZE; nI++) 
	{
		for (nJ = 0; nJ < 4; nJ++) 
		{
			if (lKeyPos == lKeyLen) lKeyPos = 0;
			lBuf <<= 8;
			lBuf |= (WORD32)(pKey[lKeyPos++] & 0x0ff);
		}
		pCtx->boxes[nI] ^= lBuf;
	}

	// now encrypt the all zero string and replace all boxes...
	zerostr[0] = zerostr[1] = 0x00000000;

	// encrypt the p- and the s-boxes (all together using the base pointer)
	for (nI = 0; nI < BOXES_SIZE; nI += 2) 
	{
		_BlowfishEncipher(pCtx, zerostr, zerostr);
		pCtx->boxes[nI]   = zerostr[0];
		pCtx->boxes[nI+1] = zerostr[1];
	}
}


// one encryption loop (swapable)
#define ENC_LOOP(LOOPNUM, LEFT, RIGHT)	\
	LEFT ^= pbox[LOOPNUM];				\
	RIGHT ^= ((sbox1[ LEFT >> 24] +		\
	sbox2[(LEFT >> 16) & 0x0ff]) ^		\
	sbox3[(LEFT >> 8) & 0x0ff]) +		\
	sbox4[ LEFT & 0x0ff];


// the encryption routine
void _BlowfishEncipher
(BLOWFISHCTX* pCtx,
 WORD32* srcbuf,
 WORD32* targetbuf) 
{
	// create box pointers for faster access   
	WORD32* pbox = &pCtx->boxes[PBOX_POS];
	WORD32* sbox1 = &pCtx->boxes[SBOX1_POS];
	WORD32* sbox2 = &pCtx->boxes[SBOX2_POS];
	WORD32* sbox3 = &pCtx->boxes[SBOX3_POS];
	WORD32* sbox4 = &pCtx->boxes[SBOX4_POS];

	// get the block
	WORD32 lLeft = srcbuf[0];
	WORD32 lRight = srcbuf[1];

	// the encryption loop (unrolled) */
	ENC_LOOP(0, lLeft, lRight)  
		ENC_LOOP(1, lRight, lLeft)  
		ENC_LOOP(2, lLeft, lRight)  
		ENC_LOOP(3, lRight, lLeft)  
		ENC_LOOP(4, lLeft, lRight)  
		ENC_LOOP(5, lRight, lLeft)  
		ENC_LOOP(6, lLeft, lRight)  
		ENC_LOOP(7, lRight, lLeft)  
		ENC_LOOP(8, lLeft, lRight)  
		ENC_LOOP(9, lRight, lLeft)  
		ENC_LOOP(10, lLeft, lRight)  
		ENC_LOOP(11, lRight, lLeft)  
		ENC_LOOP(12, lLeft, lRight)  
		ENC_LOOP(13, lRight, lLeft)  
		ENC_LOOP(14, lLeft, lRight)  
		ENC_LOOP(15, lRight, lLeft)  

	// swap, finalize and store the block back
	targetbuf[1] = lLeft ^ pbox[16];
	targetbuf[0] = lRight ^ pbox[17];
}


// the decryption routine
void _BlowfishDecipher
(BLOWFISHCTX* pCtx,
 WORD32* srcbuf,
 WORD32* targetbuf) 
{
	// create box pointers for faster access   
	WORD32* pbox = &pCtx->boxes[PBOX_POS];
	WORD32* sbox1 = &pCtx->boxes[SBOX1_POS];
	WORD32* sbox2 = &pCtx->boxes[SBOX2_POS];
	WORD32* sbox3 = &pCtx->boxes[SBOX3_POS];
	WORD32* sbox4 = &pCtx->boxes[SBOX4_POS];

	// get the block
	WORD32 lLeft = srcbuf[0];
	WORD32 lRight = srcbuf[1];

	// the decryption loop (unrolled)
	ENC_LOOP(17, lLeft, lRight)  
		ENC_LOOP(16, lRight, lLeft)  
		ENC_LOOP(15, lLeft, lRight)  
		ENC_LOOP(14, lRight, lLeft)  
		ENC_LOOP(13, lLeft, lRight)  
		ENC_LOOP(12, lRight, lLeft)  
		ENC_LOOP(11, lLeft, lRight)  
		ENC_LOOP(10, lRight, lLeft)  
		ENC_LOOP(9, lLeft, lRight)  
		ENC_LOOP(8, lRight, lLeft)  
		ENC_LOOP(7, lLeft, lRight)  
		ENC_LOOP(6, lRight, lLeft)  
		ENC_LOOP(5, lLeft, lRight)  
		ENC_LOOP(4, lRight, lLeft)  
		ENC_LOOP(3, lLeft, lRight)  
		ENC_LOOP(2, lRight, lLeft)

	// swap, finalize and store the block back
	targetbuf[1] = lLeft ^ pbox[1];
	targetbuf[0] = lRight ^ pbox[0];
}


// to check for a weak key (equal s-box entries)
BYTEBOOL _isWeakKey
(BLOWFISHCTX* pCtx) 
{
	int nI, nJ;
	for (nI = 0; nI < 255; nI++) 
	{
		for (nJ = nI + 1; nJ < 256; nJ++) 
		{
			if (pCtx->boxes[SBOX1_POS + nI] == pCtx->boxes[SBOX1_POS + nJ]) return BOOL_TRUE;   
			if (pCtx->boxes[SBOX2_POS + nI] == pCtx->boxes[SBOX2_POS + nJ]) return BOOL_TRUE;   
			if (pCtx->boxes[SBOX3_POS + nI] == pCtx->boxes[SBOX3_POS + nJ]) return BOOL_TRUE;   
			if (pCtx->boxes[SBOX4_POS + nI] == pCtx->boxes[SBOX4_POS + nJ]) return BOOL_TRUE;   
		}
	}

	// no weak key detected
	return BOOL_FALSE;
}
