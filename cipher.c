#include <sys/types.h>
#include <errno.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>

#include "cipher.h"
#include "var.h"
#include "aes.h"
#include "twofish.h"
#include "blowfish.h"
#include "tripledes.h"
#include "serpent.h"
#include "cast.h"
#include "options.h"

#define sfree free
#define smalloc malloc
#define srealloc realloc
Cipher_GetCipherInfo* pGetCipherInfo;
Cipher_SelfTest* pSelfTest;
Cipher_CreateWorkContext* pCreateWorkContext;
Cipher_ResetWorkContext* pResetWorkContext;
Cipher_DestroyWorkContext* pDestroyWorkContext;
Cipher_EncryptBuffer* pEncryptBuffer;
Cipher_DecryptBuffer* pDecryptBuffer;

#define cipher_code_aes 0
#define cipher_code_twofish 1
#define cipher_code_blowfish 2
#define cipher_code_tripledes 3
#define cipher_code_serpent 4
#define cipher_code_cast 5


char curcode = 0;
char codeset = 0;
int contextsize = 0;
int maxblocksize = 16;
int maxkeysize = 56;

void get_random_bytes(WORD8 *pbuffer, WORD32 bytes, const void* thread_null)
{
	gather_random_fast(pbuffer, bytes);
}

char getCipherCodeFromString(char *string)
{
	if ( !strcmp("aes", string) || !strcmp("rijndael", string) )
	return curcode = cipher_code_aes;
	if ( !strcmp("twofish", string) || !strcmp("tf", string) )
	return curcode = cipher_code_twofish;
	if ( !strcmp("blowfish", string) || !strcmp("bf", string) )
	return curcode = cipher_code_blowfish;
	if ( !strcmp("des", string) || !strcmp("3des", string) || !strcmp("tdes", string) )
	return curcode = cipher_code_tripledes;
	if ( !strcmp("serpent", string) || !strcmp("spnt", string) )
	return curcode = cipher_code_serpent;
	if ( !strcmp("cast", string) )
	return curcode = cipher_code_cast;
	merror("invalid cipher '%s'\n", string);
	return -1;
}

void SetCtx()
{
	switch(curcode)
	{
		case cipher_code_aes:
			opts->cipher = "aes";
			contextsize = cs_aes();
			pGetCipherInfo		= AES_GetCipherInfo;
			pSelfTest			= AES_SelfTest;
			pCreateWorkContext	= AES_CreateWorkContext;
			pResetWorkContext	= AES_ResetWorkContext;
			pDestroyWorkContext	= AES_DestroyWorkContext;
			pEncryptBuffer		= AES_EncryptBuffer;
			pDecryptBuffer		= AES_DecryptBuffer;
		break;
		case cipher_code_twofish:
			opts->cipher = "twofish";
			contextsize = cs_twofish();
			pGetCipherInfo		= Twofish_GetCipherInfo;
			pSelfTest			= Twofish_SelfTest;
			pCreateWorkContext	= Twofish_CreateWorkContext;
			pResetWorkContext	= Twofish_ResetWorkContext;
			pDestroyWorkContext	= Twofish_DestroyWorkContext;
			pEncryptBuffer		= Twofish_EncryptBuffer;
			pDecryptBuffer		= Twofish_DecryptBuffer;
		break;
		case cipher_code_blowfish:
			opts->cipher = "blowfish";
			contextsize = cs_blowfish();
			pGetCipherInfo		= Blowfish_GetCipherInfo;
			pSelfTest			= Blowfish_SelfTest;
			pCreateWorkContext	= Blowfish_CreateWorkContext;
			pResetWorkContext	= Blowfish_ResetWorkContext;
			pDestroyWorkContext	= Blowfish_DestroyWorkContext;
			pEncryptBuffer		= Blowfish_EncryptBuffer;
			pDecryptBuffer		= Blowfish_DecryptBuffer;
		break;
		case cipher_code_tripledes:
			opts->cipher = "3des";
			contextsize = cs_tripledes();
			pGetCipherInfo		= TripleDES_GetCipherInfo;
			pSelfTest		= TripleDES_SelfTest;
			pCreateWorkContext	= TripleDES_CreateWorkContext;
			pResetWorkContext	= TripleDES_ResetWorkContext;
			pDestroyWorkContext	= TripleDES_DestroyWorkContext;
			pEncryptBuffer		= TripleDES_EncryptBuffer;
			pDecryptBuffer		= TripleDES_DecryptBuffer;
		break;
		case cipher_code_serpent:
			opts->cipher = "serpent";
			contextsize = cs_serpent();
			pGetCipherInfo		= Serpent_GetCipherInfo;
			pSelfTest		= Serpent_SelfTest;
			pCreateWorkContext	= Serpent_CreateWorkContext;
			pResetWorkContext	= Serpent_ResetWorkContext;
			pDestroyWorkContext	= Serpent_DestroyWorkContext;
			pEncryptBuffer		= Serpent_EncryptBuffer;
			pDecryptBuffer		= Serpent_DecryptBuffer;
		break;
		case cipher_code_cast:
			opts->cipher = "cast";
			contextsize = cs_cast();
			pGetCipherInfo		= CAST_GetCipherInfo;
			pSelfTest		= CAST_SelfTest;
			pCreateWorkContext	= CAST_CreateWorkContext;
			pResetWorkContext	= CAST_ResetWorkContext;
			pDestroyWorkContext	= CAST_DestroyWorkContext;
			pEncryptBuffer		= CAST_EncryptBuffer;
			pDecryptBuffer		= CAST_DecryptBuffer;
		break;
		default:
			merror("invalid cipher code detected %d", curcode);
		break;
	}
}

void *determineCipherContext(char* cipher)
{
	void *ctx;
	if ( !codeset )
	curcode = getCipherCodeFromString(cipher);
	if(curcode == -1) { return NULL; }

	SetCtx();

	ctx = (void*) smalloc(contextsize);
	if (!ctx) {
		merror("could not allocate memory for cipher context: %s", strerror(errno));
		return NULL;
	}

	if ( curcode == cipher_code_aes )
	{ curkeysize = 32; curblocksize = 16; }
	if ( curcode == cipher_code_twofish )
	{ curkeysize = 32; curblocksize = 16; }
	if ( curcode == cipher_code_blowfish )
	{ curkeysize = 56; curblocksize = 8; }
	if ( curcode == cipher_code_tripledes )
	{ curkeysize = 21; curblocksize = 8; }
	if ( curcode == cipher_code_serpent )
	{ curkeysize = 32; curblocksize = 16; }
	if ( curcode == cipher_code_cast )
	{ curkeysize = 16; curblocksize = 8; }

	return ctx;
}

void *freeCipherContext(void* ctx)
{
	if ( ctx ) (*pDestroyWorkContext)(ctx);
	if ( ctx ) sfree(ctx);
}

