#include "hmac_sha1.h"
#include "sha1.h"
#include <string.h>

#define IPAD_CONST 0x36
#define OPAD_CONST 0x5c

/*
 * This computes an HMAC-SHA1, given a key and some data
 */
void hmac_sha1( const void *key, unsigned len_key,
                const void *data, unsigned len_data,
                unsigned char *output ) {
    SHA1_CTX ctx;
    unsigned char key_buffer[ SHA1_LEN ];
    unsigned char ipad[ SHA1_BLOCK_SIZE ];
    unsigned char opad[ SHA1_BLOCK_SIZE ];
    unsigned char ipad_result[ SHA1_LEN ];
    unsigned i;
    const unsigned char *p;

    /* HMAC handles long keys by hashing them */
    if (len_key > SHA1_BLOCK_SIZE) {
        SHA1Init( &ctx );
        SHA1Update( &ctx, key, len_key );
        SHA1Final( key_buffer, &ctx );
        key = key_buffer;
        len_key = SHA1_LEN;
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
    SHA1Init( &ctx );
    SHA1Update( &ctx, ipad, sizeof ipad );
    SHA1Update( &ctx, data, len_data );
    SHA1Final( ipad_result, &ctx );

    /* Perform the outer hash; the result of that is the HMAC */
    SHA1Init( &ctx );
    SHA1Update( &ctx, opad, sizeof opad );
    SHA1Update( &ctx, ipad_result, sizeof ipad_result );
    SHA1Final( output, &ctx );
}
