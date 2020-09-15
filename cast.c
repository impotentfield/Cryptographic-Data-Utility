/*
*
* CAST-128 (also known as CAST5)
* implementing the CAST-128 algorithm in CBC mode
*
* Written by Walter Dvorak <e9226745@student.tuwien.ac.at>
*
* For details in the CAST Encryption Algorithm please refer:
* [1] C. Adams, "Constructing Symmetric Ciphers Using the CAST
*                Design Procedure", in
*     Selected Areas in Cryptography, Kluwer Academic Publishers,
*     1997, pp. 71-104.
*
* This work based in parts on a cast-128 implementation
*   for OpenBSD from Steve Reid <sreid@sea-to-sky.net>
*
* modified to fit into CryptPak by Markus Hahn
* (on 12 April 2000)
*
* source code reformatted by Markus Hahn (00/08/04)
* const modifiers added by Markus Hahn (00/09/29)
* ineffective code removed by Markus Hahn (01/07/29)
* adapted to standard cryptpak by Markus Hahn (04/03/25)
*
* This program is Public Domain
*
* Some notes:
*  1. CAST 16-rounds/128bit key only implementation. No support
*     for 12-rounds/ 80bit key version.
*  2. In _BIGTEST compiled version, the selftest is a full
*     maintenance test, specifed in appendix C in [1]
*
* Date: 26.9.1998
*
*/

#include "cast.h"
#include "ciphervar.h"

#undef _BIGTEST

/*
* S-Boxes for CAST-128
*/
#include "cast_boxes.h"

/*
* CAST5 work context
*/
typedef struct 
{
	WORD32 xkey[32];                     /* Key after expansion */
	WORD32 lCBCLo;                       /* CBC IV */
	WORD32 lCBCHi;
	BYTEBOOL blLegacy;
} 
CASTCTX;

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


/*
* Macros to access 8-bit bytes out of a 32-bit word
*/
#define U8a(x) ( (WORD8)  (x>>24)      )
#define U8b(x) ( (WORD8) ((x>>16) &255))
#define U8c(x) ( (WORD8) ((x>>8)  &255))
#define U8d(x) ( (WORD8) ((x)     &255))

/*
* Circular left shift
*/
#define ROL(x, n) ( ((x)<<(n)) | ((x)>>(32-(n))) )

/*
* CAST-128 uses three different round functions
*/
#define F1(l, r, i) \
	t = ROL(key->xkey[i] + r, key->xkey[i+16]); \
	l ^= ((cast_sbox1[U8a(t)] ^ cast_sbox2[U8b(t)]) - \
	cast_sbox3[U8c(t)]) + cast_sbox4[U8d(t)];

#define F2(l, r, i) \
	t = ROL(key->xkey[i] ^ r, key->xkey[i+16]); \
	l ^= ((cast_sbox1[U8a(t)] - cast_sbox2[U8b(t)]) + \
	cast_sbox3[U8c(t)]) ^ cast_sbox4[U8d(t)];

#define F3(l, r, i) \
	t = ROL(key->xkey[i] - r, key->xkey[i+16]); \
	l ^= ((cast_sbox1[U8a(t)] + cast_sbox2[U8b(t)]) ^ \
	cast_sbox3[U8c(t)]) - cast_sbox4[U8d(t)];


/*
* CAST Encryption Function
*/
void _cast_encrypt
(CASTCTX* key, 
 WORD32* inblock, 
 WORD32* outblock)
{
	register WORD32 t, l, r;

	/* Get inblock into l,r */
	l = inblock[0];
	r = inblock[1];

	/* unrolled encryption loop */
	F1(l, r,  0);
	F2(r, l,  1);
	F3(l, r,  2);
	F1(r, l,  3);
	F2(l, r,  4);
	F3(r, l,  5);
	F1(l, r,  6);
	F2(r, l,  7);
	F3(l, r,  8);
	F1(r, l,  9);
	F2(l, r, 10);
	F3(r, l, 11);
	F1(l, r, 12);
	F2(r, l, 13);
	F3(l, r, 14);
	F1(r, l, 15);

	/* Put l,r into outblock */
	outblock[0] = r;
	outblock[1] = l;
}


/*
* Decryption Function
*/
void _cast_decrypt
(CASTCTX* key, 
 WORD32* inblock, 
 WORD32* outblock)
{
	register WORD32 t, l, r;

	/* Get inblock into l,r */
	r = inblock[0];
	l = inblock[1];

	F1(r, l, 15);
	F3(l, r, 14);
	F2(r, l, 13);
	F1(l, r, 12);
	F3(r, l, 11);
	F2(l, r, 10);
	F1(r, l,  9);
	F3(l, r,  8);
	F2(r, l,  7);
	F1(l, r,  6);
	F3(r, l,  5);
	F2(l, r,  4);
	F1(r, l,  3);
	F3(l, r,  2);
	F2(r, l,  1);
	F1(l, r,  0);

	/* Put l,r into outblock */
	outblock[0] = l;
	outblock[1] = r;
}


/*
* Key Schedule
*/
void _cast_setkey
(CASTCTX* key, 
 WORD8* rawkey, 
 WORD32 keybytes)
{
	WORD32 t[4], z[4], x[4];
	unsigned int i;

	/* Copy key to workspace */
	for (i = 0; i < 4; i++) 
	{
		x[i] = 0;
		if ((i*4+0) < keybytes) x[i] = (WORD32)rawkey[i*4+0] << 24;
		if ((i*4+1) < keybytes) x[i] |= (WORD32)rawkey[i*4+1] << 16;
		if ((i*4+2) < keybytes) x[i] |= (WORD32)rawkey[i*4+2] << 8;
		if ((i*4+3) < keybytes) x[i] |= (WORD32)rawkey[i*4+3];
	}
	/* Generate 32 subkeys, four at a time */
	for (i = 0; i < 32; i+=4) 
	{
		switch (i & 4) 
		{
		case 0:
			t[0] = z[0] = x[0] ^ cast_sbox5[U8b(x[3])] ^
				cast_sbox6[U8d(x[3])] ^ cast_sbox7[U8a(x[3])] ^
				cast_sbox8[U8c(x[3])] ^ cast_sbox7[U8a(x[2])];
			t[1] = z[1] = x[2] ^ cast_sbox5[U8a(z[0])] ^
				cast_sbox6[U8c(z[0])] ^ cast_sbox7[U8b(z[0])] ^
				cast_sbox8[U8d(z[0])] ^ cast_sbox8[U8c(x[2])];
			t[2] = z[2] = x[3] ^ cast_sbox5[U8d(z[1])] ^
				cast_sbox6[U8c(z[1])] ^ cast_sbox7[U8b(z[1])] ^
				cast_sbox8[U8a(z[1])] ^ cast_sbox5[U8b(x[2])];
			t[3] = z[3] = x[1] ^ cast_sbox5[U8c(z[2])] ^
				cast_sbox6[U8b(z[2])] ^ cast_sbox7[U8d(z[2])] ^
				cast_sbox8[U8a(z[2])] ^ cast_sbox6[U8d(x[2])];
			break;
		case 4:
			t[0] = x[0] = z[2] ^ cast_sbox5[U8b(z[1])] ^
				cast_sbox6[U8d(z[1])] ^ cast_sbox7[U8a(z[1])] ^
				cast_sbox8[U8c(z[1])] ^ cast_sbox7[U8a(z[0])];
			t[1] = x[1] = z[0] ^ cast_sbox5[U8a(x[0])] ^
				cast_sbox6[U8c(x[0])] ^ cast_sbox7[U8b(x[0])] ^
				cast_sbox8[U8d(x[0])] ^ cast_sbox8[U8c(z[0])];
			t[2] = x[2] = z[1] ^ cast_sbox5[U8d(x[1])] ^
				cast_sbox6[U8c(x[1])] ^ cast_sbox7[U8b(x[1])] ^
				cast_sbox8[U8a(x[1])] ^ cast_sbox5[U8b(z[0])];
			t[3] = x[3] = z[3] ^ cast_sbox5[U8c(x[2])] ^
				cast_sbox6[U8b(x[2])] ^ cast_sbox7[U8d(x[2])] ^
				cast_sbox8[U8a(x[2])] ^ cast_sbox6[U8d(z[0])];
			break;
		}
		switch (i & 12) 
		{
		case 0:
		case 12:
			key->xkey[i+0] = cast_sbox5[U8a(t[2])] ^ cast_sbox6[U8b(t[2])] ^
				cast_sbox7[U8d(t[1])] ^ cast_sbox8[U8c(t[1])];
			key->xkey[i+1] = cast_sbox5[U8c(t[2])] ^ cast_sbox6[U8d(t[2])] ^
				cast_sbox7[U8b(t[1])] ^ cast_sbox8[U8a(t[1])];
			key->xkey[i+2] = cast_sbox5[U8a(t[3])] ^ cast_sbox6[U8b(t[3])] ^
				cast_sbox7[U8d(t[0])] ^ cast_sbox8[U8c(t[0])];
			key->xkey[i+3] = cast_sbox5[U8c(t[3])] ^ cast_sbox6[U8d(t[3])] ^
				cast_sbox7[U8b(t[0])] ^ cast_sbox8[U8a(t[0])];
			break;
		case 4:
		case 8:
			key->xkey[i+0] = cast_sbox5[U8d(t[0])] ^ cast_sbox6[U8c(t[0])] ^
				cast_sbox7[U8a(t[3])] ^ cast_sbox8[U8b(t[3])];
			key->xkey[i+1] = cast_sbox5[U8b(t[0])] ^ cast_sbox6[U8a(t[0])] ^
				cast_sbox7[U8c(t[3])] ^ cast_sbox8[U8d(t[3])];
			key->xkey[i+2] = cast_sbox5[U8d(t[1])] ^ cast_sbox6[U8c(t[1])] ^
				cast_sbox7[U8a(t[2])] ^ cast_sbox8[U8b(t[2])];
			key->xkey[i+3] = cast_sbox5[U8b(t[1])] ^ cast_sbox6[U8a(t[1])] ^
				cast_sbox7[U8c(t[2])] ^ cast_sbox8[U8d(t[2])];
			break;
		}
		switch (i & 12) 
		{
		case 0:
			key->xkey[i+0] ^= cast_sbox5[U8c(z[0])];
			key->xkey[i+1] ^= cast_sbox6[U8c(z[1])];
			key->xkey[i+2] ^= cast_sbox7[U8b(z[2])];
			key->xkey[i+3] ^= cast_sbox8[U8a(z[3])];
			break;
		case 4:
			key->xkey[i+0] ^= cast_sbox5[U8a(x[2])];
			key->xkey[i+1] ^= cast_sbox6[U8b(x[3])];
			key->xkey[i+2] ^= cast_sbox7[U8d(x[0])];
			key->xkey[i+3] ^= cast_sbox8[U8d(x[1])];
			break;
		case 8:
			key->xkey[i+0] ^= cast_sbox5[U8b(z[2])];
			key->xkey[i+1] ^= cast_sbox6[U8a(z[3])];
			key->xkey[i+2] ^= cast_sbox7[U8c(z[0])];
			key->xkey[i+3] ^= cast_sbox8[U8c(z[1])];
			break;
		case 12:
			key->xkey[i+0] ^= cast_sbox5[U8d(x[0])];
			key->xkey[i+1] ^= cast_sbox6[U8d(x[1])];
			key->xkey[i+2] ^= cast_sbox7[U8a(x[2])];
			key->xkey[i+3] ^= cast_sbox8[U8b(x[3])];
			break;
		}
		if (i >= 16) 
		{
			key->xkey[i+0] &= 31;
			key->xkey[i+1] &= 31;
			key->xkey[i+2] &= 31;
			key->xkey[i+3] &= 31;
		}
	}
	/* Wipe clean */
	for (i = 0; i < 4; i++) 
	{
		t[i] = x[i] = z[i] = 0;
	}
}

int cs_cast()
{
	return sizeof(CASTCTX);
}

/*
* GetDriver Info
*/
WORD32 CAST_GetCipherInfo
(CIPHERINFOBLOCK* pInfo) 
{
	WORD32 lI;
	WORD8* pSrc;
	WORD8* pDst;
	CIPHERINFOBLOCK tempinfo;

	// prepare the information context
	tempinfo.lSizeOf = pInfo->lSizeOf;
	tempinfo.lBlockSize = 8;
	tempinfo.lKeySize = 16; 
	tempinfo.blOwnHasher = BOOL_FALSE;
	tempinfo.lInitDataSize = 8;
	tempinfo.lContextSize = sizeof(CASTCTX);
	tempinfo.bCipherIs = CIPHER_IS_BLOCKLINK;

	// copy as many bytes of the information block as possible
	pSrc = (WORD8*) &tempinfo;
	pDst = (WORD8*) pInfo;
	for (lI = 0; lI < tempinfo.lSizeOf; lI++) 
	{ 
		*pDst++ = *pSrc++;
	}

	return CIPHER_ERROR_NOERROR;
}



/*
* Driver Selftest
*/
WORD32 CAST_SelfTest 
(void* pTestContext) 
{
#ifdef _BIGTEST

	WORD32 a[4] = { 0x01234567, 0x12345678, 
		            0x23456789, 0x3456789a };
	WORD32 b[4] = { 0x01234567, 0x12345678, 
		            0x23456789, 0x3456789a };

	WORD32 av[4] = { 0xeea9d0a2, 0x49fd3ba6, 
		             0xb3436fb8, 0x9d6dca92 };
	WORD32 bv[4] = { 0xb2c95eb0, 0x0c31ad71, 
		             0x80ac05b8, 0xe83d696e };
	
	WORD8 akey[16];
	WORD8 bkey[16];
#endif

	int nI;

	/* test the driver for correct encrypting and decrypting... */
	CASTCTX* testCtx = (CASTCTX*) pTestContext;

	/* offical test vector from C. Adams; For details see [1] */
	WORD8 testKey[16] = { 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
		                  0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A };
	WORD32 tv_p[2] = { 0x01234567, 0x89abcdef };
	WORD32 tv_c[2] = { 0x238b4fe5, 0x847e44b2 };
	WORD32 tv_t[2] = { 0x00000000, 0x00000000 };

	/* legacy does not matter here actually */
	testCtx->blLegacy = BOOL_FALSE;

	_cast_setkey(testCtx, testKey, 16);

	_cast_encrypt(testCtx, tv_p, tv_t);
	for (nI = 0; nI < sizeof(tv_t); nI++)
	  if ((tv_t[0] != tv_c[0]) || (tv_t[1] != tv_c[1]))
		return CIPHER_ERROR_INVALID;

	_cast_decrypt(testCtx, tv_t, tv_t);
	for (nI = 0; nI < sizeof(tv_t); nI++)
	  if ((tv_t[0] != tv_p[0]) || (tv_t[1] != tv_p[1]))
		return CIPHER_ERROR_INVALID;

	/* Only in the debug version is a full maintenance test
	* included. This test verify "very hard" the correctness
	* of the implementation and S-boxes. Please refer [1] for
	* more details. This test take up to some minutes,
	* depending on the CPU speed, so please dont get confused.
	*/

#ifdef _BIGTEST

	for (nI = 0 ; nI < 1000000 ; nI++) 
	{
		WORD32_TO_BYTES(b[0], bkey)
		WORD32_TO_BYTES(b[1], bkey + 4)
		WORD32_TO_BYTES(b[2], bkey + 8)
		WORD32_TO_BYTES(b[3], bkey + 12)

		_cast_setkey (testCtx, bkey, sizeof(bkey));
		_cast_encrypt(testCtx, &a[0], &a[0]);
		_cast_encrypt(testCtx, &a[8], &a[8]);

		WORD32_TO_BYTES(a[0], akey)
		WORD32_TO_BYTES(a[1], akey + 4)
		WORD32_TO_BYTES(a[2], akey + 8)
		WORD32_TO_BYTES(a[3], akey + 12)

		_cast_setkey (testCtx, a, sizeof(a));
		_cast_encrypt(testCtx, &b[0], &b[0]);
		_cast_encrypt(testCtx, &b[8], &b[8]);
	}
	for (nI = 0; nI < sizeof(a); nI++)
	  if (a[nI] - av[nI])
		return CIPHER_ERROR_INVALID;

	for (nI = 0; nI < sizeof(b); nI++)
	  if (b[nI] - bv[nI])
		return CIPHER_ERROR_INVALID;
#endif

	/* Test passes */
	return CIPHER_ERROR_NOERROR;
}

#define CIPHER_GETMODE(lmode) (lmode)

/*
* Create Work Context
*/
WORD32 CAST_CreateWorkContext
(void* pContext,
 const WORD8* pKey,
 WORD32 lKeyLen,
 WORD32 lMode,
 void* pInitData,
 Cipher_RandomGenerator GetRndBytes,
 const void* pRndGenData) 
{
	WORD8* pbInit;
	CASTCTX* pCtx = (CASTCTX*) pContext;

	/* check if we keep up to the standard */
	pCtx->blLegacy = 0;/*(CIPHER_GETFLAGS(lMode) & CIPHER_MODE_FLAG_LEGACY) ?
		BOOL_TRUE : BOOL_FALSE;*/

	/* do the key setup */
	_cast_setkey(pCtx, (WORD8*)pKey, lKeyLen);

if ( cipher_block_mode == CIPHER_MODE_CBC ) {
	/* for encryption create a CBC IV */
	pbInit = (WORD8*) pInitData;
	if (CIPHER_GETMODE(lMode) == CIPHER_MODE_ENCRYPT)
		GetRndBytes(pbInit, 8, pRndGenData); 

	/* set the CBC IV */
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
	/* In CAST are no weak keys known */
	return CIPHER_ERROR_NOERROR;
}

/*
* Reset Work Context
*/
void CAST_ResetWorkContext
(void* pContext,
 WORD32 lMode,
 void* pInitData,
 Cipher_RandomGenerator GetRndBytes,
 const void* pRndGenData) 
{
	CASTCTX* pCtx = (CASTCTX*) pContext;

	/* just reset the CBC IV */
	WORD8* pbInit = (WORD8*) pInitData;
	if (CIPHER_GETMODE(lMode) == CIPHER_MODE_ENCRYPT)
		GetRndBytes(pbInit, 8, pRndGenData); 

	/* set the CBC IV */
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


/*
* Destroy Work Context
*/
WORD32 CAST_DestroyWorkContext
(void* pContext) 
{
	/* clear the context */
	int nI;
	WORD8* clearIt = (WORD8*) pContext;
	for (nI = 0; nI < sizeof(CASTCTX); nI++) clearIt[nI] = 0x00;
	return CIPHER_ERROR_NOERROR;
}

#define WORD32_REVERSE_ORDER(x) (x) /*WARNING!: we dont use bllegacy in here */
/*
* Encrypt Buffer
*/
void CAST_EncryptBuffer
(void* pContext,
 const void* pSource,
 void* pTarget,
 WORD32 lNumOfBytes) 
{
	WORD32 lI;
	WORD32 blk[2];
	WORD8* pbIn = (WORD8*) pSource;
	WORD8* pbOut = (WORD8*) pTarget;
	CASTCTX* pCtx = (CASTCTX*) pContext;

	/* anything to encrypt? */
	lNumOfBytes &= ~7;
	if (0 == lNumOfBytes) return;

	/* work through all blocks... */
	for (lI = 0; lI < lNumOfBytes; lI += 8) 
	{
		/* get and chain the block */
		if (pCtx->blLegacy)
		{
if ( cipher_block_mode == CIPHER_MODE_CBC ) {
			blk[0] = BYTES_TO_WORD32_X86(pbIn) ^ pCtx->lCBCLo;
			blk[1] = BYTES_TO_WORD32_X86(pbIn + 4) ^ pCtx->lCBCHi;
} else {			
			blk[0] = BYTES_TO_WORD32_X86(pbIn);
			blk[1] = BYTES_TO_WORD32_X86(pbIn + 4);
}
			blk[0] = WORD32_REVERSE_ORDER(blk[0]);
			blk[1] = WORD32_REVERSE_ORDER(blk[1]);
		}
		else
		{
if ( cipher_block_mode == CIPHER_MODE_CBC ) {
			blk[0] = BYTES_TO_WORD32(pbIn) ^ pCtx->lCBCHi;
			blk[1] = BYTES_TO_WORD32(pbIn + 4) ^ pCtx->lCBCLo;
} else {
			blk[0] = BYTES_TO_WORD32(pbIn);
			blk[1] = BYTES_TO_WORD32(pbIn + 4);
}

		}
		pbIn += 8;

		// encrypt the block
		_cast_encrypt(pCtx, blk, blk);

		/* copy it back and set the new CBC IV */
		if (pCtx->blLegacy)
		{
			WORD32_TO_BYTES(blk[0], pbOut)
			WORD32_TO_BYTES(blk[1], pbOut + 4)
if ( cipher_block_mode == CIPHER_MODE_CBC ) {
			pCtx->lCBCLo = WORD32_REVERSE_ORDER(blk[0]);
			pCtx->lCBCHi = WORD32_REVERSE_ORDER(blk[1]);
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

/*
* Decrypt Buffer
*/
void CAST_DecryptBuffer
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
	CASTCTX* pCtx = (CASTCTX*) pContext;

	/* anything to decrypt? */
	if (0 == (lNumOfBytes &= ~7)) return;

if ( cipher_block_mode == CIPHER_MODE_CBC ) {
	/* load a new CBC IV, if necessary */
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
	/* work through all blocks... */ 
	for (lI = 0; lI < lNumOfBytes; lI += 8) 
	{
		/* load the current block */
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
		/* save the recent CBC IV */ 
		saveIV[0] = blk[0];
		saveIV[1] = blk[1];
}
		
		if (pCtx->blLegacy)
		{
			blk[0] = WORD32_REVERSE_ORDER(blk[0]);
			blk[1] = WORD32_REVERSE_ORDER(blk[1]);
		}

		/* decrypt the block */ 
		_cast_decrypt(pCtx, blk, blk);

		/* unchain the recent block and set the new IV */

		if (pCtx->blLegacy)
		{
			blk[0] = WORD32_REVERSE_ORDER(blk[0]);
			blk[1] = WORD32_REVERSE_ORDER(blk[1]);
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


/*
* Thats all for now, folks
*/
