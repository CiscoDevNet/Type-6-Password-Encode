#include <stdlib.h>
#include <string.h>
#include "hmac_sha256.h"
#include "pbkdf2.h"
#include "endian.h"

/* Compute a/b, rounding upwards */
#define ROUND_UP(a, b)  ((a + b - 1) / b)

/* Exclusive-or the block of data at 'from' into the block of data at 'to' */
static void do_xor(unsigned char *to, const unsigned char *from, unsigned int len) {
    while (len--) {
        *to++ ^= *from++;
    }
}

/*
 * This is the function F defined within section 5.2 of RFC2898
 */
static int F(const char *password, unsigned password_len,
             const char * salt, unsigned int salt_len,
             unsigned int iterations, unsigned int i,
             unsigned char *buffer) {
    unsigned char prev_u[HMAC_SHA256_LEN];
#define I_LENGTH 4 /* 4 is specified in the RFC */
    unsigned int j;
    unsigned char *salt_and_i_buffer;

    /*
     * Compute U_1
     */
    salt_and_i_buffer = (unsigned char*)malloc(salt_len + I_LENGTH);
    if (!salt_and_i_buffer) return 0;  /* Malloc failure */
    /* Concatinate the salt and the 4 byte iteration count (i) */
    for (j=0; j<salt_len; j++) {
        salt_and_i_buffer[j] = salt[j];
    }
    put_ulong_bigendian( salt_and_i_buffer+j, i );
    j += I_LENGTH;

    hmac_sha256( password, password_len,
                 salt_and_i_buffer, j,
                 prev_u );   
    memcpy( buffer, prev_u, HMAC_SHA256_LEN);
    free(salt_and_i_buffer);

    /*
     * Now, compute each U_j in succession 
     */
    for (j=2; j<=iterations; j++) {
        unsigned char temp[HMAC_SHA256_LEN];
        hmac_sha256( password, password_len,
                     prev_u, sizeof prev_u,
                     temp );
        memcpy( prev_u, temp, HMAC_SHA256_LEN );

        do_xor(buffer, prev_u, HMAC_SHA256_LEN);
    }

    return 1;  /* We  succeeded */
}

/*
 * This is the PBKDF2 function (as defined in RFC2898), using SHA256 as the
 * underlying hash function
 * The comments are from the algorithm in RFC2898, setion 5.2
 */
int pbkdf2_sha256(const char *password, unsigned int password_len,
                  const char *salt, unsigned int salt_len,
                  unsigned iterations,
                  unsigned char *output, unsigned int output_len)
{
    unsigned output_blocks, r;
    unsigned i;

    if (!password || !salt || !output ) {
         return 0;
    }

    /*
     * Step 1: sanity check the output_len
     * Since we really don't support buffers of length >100Gigabytes, we can
     * skip this step
     */

    /*
     * Step 2: let output_blocks be the number of output blocks in the derived
     * key, and let r be the number of octets in the last block
     * The RFC has the variable l rather than output_blocks; however, l is an
     * evil variable name
     */
    output_blocks = ROUND_UP(output_len, HMAC_SHA256_LEN);
    r = output_len - (output_blocks-1)*HMAC_SHA256_LEN;

    /*
     * Step 3: for each block, apply the function F to generate the block
     */
    for (i=1; i<=output_blocks; i++) {
        unsigned char buffer[HMAC_SHA256_LEN];

        if (!F(password, password_len, salt, salt_len, iterations, i, buffer)) {
            /* Failure is an option */
            return 0;
        }

        if (i==output_blocks) {

            /* This is the final block; copy only what we need */
            memcpy( output, buffer, r );

        } else {
            /* This is an intermediate block; we use the entire F output */
            memcpy( output, buffer, HMAC_SHA256_LEN );

            /* Place the next output immediately after this one */
            output += HMAC_SHA256_LEN;
        }
    }

    /*
     * Step 4: concatenate the blocks.
     * We skip this step, because we already did that as a part of step 3
     */

    /*
     * Step 5: output the derived key
     */
    return 1;  /* We did it */
}
