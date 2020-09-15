#include "basictypes.h"
#include "cipherdef.h"
#include "cipherenable.h"

extern char curcode;
extern char codeset;
extern int maxkeysize;
extern int maxblocksize;

extern Cipher_GetCipherInfo* pGetCipherInfo;
extern Cipher_SelfTest* pSelfTest;
extern Cipher_CreateWorkContext* pCreateWorkContext;
extern Cipher_ResetWorkContext* pResetWorkContext;
extern Cipher_DestroyWorkContext* pDestroyWorkContext;
extern Cipher_EncryptBuffer* pEncryptBuffer;
extern Cipher_DecryptBuffer* pDecryptBuffer;

void get_random_bytes(WORD8 *pbuffer, WORD32 bytes, const void *thread_null);

void *determineCipherContext(char* cipher);
void *freeCipherContext(void* ctx);
