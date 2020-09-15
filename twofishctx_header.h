#include "basictypes.h"

typedef struct
{
	// expanded S-boxes
	WORD32 sbox[4 * 256];
	// round subkeys, input/output whitening bits
	WORD32 subKeys[8 + 32];
	// CBC initalisation vector
	WORD32 cbc_iv[4];

} TWOFISHCTX;
