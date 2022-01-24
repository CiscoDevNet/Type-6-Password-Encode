#include "hmac_sha256.h"
#include "sha256.h"
#include <string.h>

#define SHA256_BLOCK_SIZE 64
#define IPAD_CONST 0x36
#define OPAD_CONST 0x5c

/*
 * This computes an HMAC-SHA256, given a key and some data
 */
void hmac_sha256( const void *key, unsigned len_key,
                  const void *data, unsigned len_data,
                  unsigned char *output ) {
    SHA256_CTX ctx;
    unsigned char key_buffer[ SHA256_LEN ];
    unsigned char ipad[ SHA256_BLOCK_SIZE ];
    unsigned char opad[ SHA256_BLOCK_SIZE ];
    unsigned char ipad_result[ SHA256_LEN ];
    unsigned i;
    const unsigned char *p;

    /* HMAC handles long keys by hashing them */
    if (len_key > SHA256_BLOCK_SIZE) {
        SHA256Init( &ctx );
        SHA256Update( &ctx, key, len_key );
        SHA256Final( key_buffer, &ctx );
        key = key_buffer;
        len_key = SHA256_LEN;
    }

    /* Compute the ipad/opad blocks */
    memset( ipad, IPAD_CONST, sizeof ipad );
    memset( opad, OPAD_CONST, sizeof opad );
    p = key;
    for (i=0; i<len_key; i++) {
        ipad[i] ^= p[i] & 0xff;
        opad[i] ^= p[i] & 0xff;
    }

    /* Perform the inner hash */
    SHA256Init( &ctx );
    SHA256Update( &ctx, ipad, sizeof ipad );
    SHA256Update( &ctx, data, len_data );
    SHA256Final( ipad_result, &ctx );

    /* Perform the outer hash; the result of that is the HMAC */
    SHA256Init( &ctx );
    SHA256Update( &ctx, opad, sizeof opad );
    SHA256Update( &ctx, ipad_result, sizeof ipad_result );
    SHA256Final( output, &ctx );
}
