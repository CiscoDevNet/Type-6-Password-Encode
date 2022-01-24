/*
 * This is an implementation of the scrypt hash function, as defined in
 * http://tools.ietf.org/id/draft-josefsson-scrypt-kdf-01.txt
 *
 * The version comments refer to sections from that internet draft
 */
#include <stdlib.h>
#include <string.h>
#include "scrypt.h"
#include "pbkdf2.h"
#include "endian.h"

/*
 * This is the salsa20/8 core function, defined in section 2 of the draft
 */
static unsigned long R(unsigned long a, int b) {
    a &= 0xffffffff;
    unsigned long left  = (a <<  b    ) & 0xffffffff;
    unsigned long right = (a >> (32-b));
    return left | right;
}
static void salsa208_word_specification(unsigned long out[16], const unsigned long in[16]) {
     int i;
     unsigned long x[16];
     for (i = 0;i < 16; i++) x[i] = in[i];
     for (i = 8;i > 0;i -= 2) {
       x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
       x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);
       x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
       x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);
       x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
       x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);
       x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
       x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);
       x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
       x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);
       x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
       x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);
       x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
       x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);
       x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
       x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
     }
     for (i = 0; i<16 ; i++) out[i] = (x[i] + in[i]) & 0xffffffff;
}

/*
 * This is the scryptBlockMix algorithm, as described in section 3
 *
 * Warning: we do not support B == B_prime; they must point to distinct arrays
 */
static void scryptBlockMix(unsigned r, const unsigned long *B, unsigned long *B_prime) {
    unsigned long X[16];
    unsigned long T[16];
    unsigned i;

    /* Step 1: grab the X value */
    memcpy( X, &B[ (2*r-1) * 16], 16 * sizeof(unsigned long));

    /* Step 2: repeatedly run the salsa hash */
    for (i=0; i<=2*r-1; i++) {
        int j;
        int output_index;

        for (j=0; j<16; j++) {
            T[j] = X[j] ^ B[ i * 16 + j ];
        }
        salsa208_word_specification(X, T);

        /* Figure out where in the B' array the hash goes */
        output_index = i/2;
        if (i & 1) output_index += r;
        memcpy( B_prime + 16*output_index, X, 16 * sizeof(unsigned long));
    }

    /* 
     * Step 3: reorder the Y array into the B' array.  Now, because of the
     * clever way we worked with output_index, we've already put things into
     * the order the caller expects
     */

    memset( X, 0, sizeof X );
    memset( T, 0, sizeof T );
}

/*
 * This is the scryptROMix routine
 */
static int scryptROMix(unsigned r, const unsigned long *B, size_t N, unsigned long *B_prime) {
    unsigned long *X, *X_alt;
    unsigned long *V;  /* This is an array of N elements, each element */
                       /* consisting of 32*r unsigned long's */
    size_t i;
    unsigned k;
    unsigned long *temp;

    /*
     * Do a sanity check against overflow; this is needed in case we run into a
     * C implementation with a tiny size_t
     */
    {
        size_t max_mem = ~(size_t)0;
        max_mem /= N;
        max_mem /= (32*r);
        max_mem /= sizeof (unsigned long);
        if (max_mem == 0) return 0;  /* We have no hope */
    }

    /* First off; allocate the memory we'll need */
    X      = (unsigned long *)malloc( 32 * r * sizeof (unsigned long) );
    X_alt  = (unsigned long *)malloc( 32 * r * sizeof (unsigned long) );
    V      = (unsigned long *)malloc( N * 32 * r * sizeof (unsigned long) );
    if (!X || !X_alt || !V) {
        free(X);
        free(X_alt);
        free(V);
        return 0;
    }
    /* Note that we'll swap X, X_alt on occasion; they'll both always point */
    /* into the original two malloc'ed space */

    /* Step 1: save B */
    for (i=0; i<32*r; i++) {
        X[i] = B[i];
    }

    /* Step 2: run scryptBlockMix in OFB mode, saving the values in the V array */
    for (i=0; i<N; i++) {

        /* V[i] = X; */
        for (k=0; k<32*r; k++) {
            V[ i*32*r + k ] = X[k];
        }

        /* X = scryptBlockMix(X) */
        /*
         * Note: our scryptBlockMix can't handle input and output being the
         * same; get around that by using two buffers, and pingponging
         */
        scryptBlockMix(r, X, X_alt);        /* Mix X, generating output into X_alt */
        temp = X; X = X_alt; X_alt = temp;  /* Swap X and X_alt */
    }

    /* Step 3: randomly iterate through the large array we just created */
    for (i=0; i<N; i++) {
        unsigned long *T = X_alt;;

        /* j = Integerify( X ) */
        size_t j = X[32*r-16] % N;

        /* T = X xor V[j] */
        for (k=0; k<32*r; k++) {
            T[k] = X[k] ^ V[j*32*r+k];
        }

        /* X = scryptBlockMix(T) */
        scryptBlockMix(r, T, X);
    }

    /* Step 4: B' = X */
    for (k=0; k<32*r; k++) {
        B_prime[k] = X[k];
    }

    /* Free up the space we allocated */
    free(X);
    free(X_alt);
    free(V);

    return 1;
}

/*
 * This returns nonzero if n is a power of two (e.g. 1, 2, 4, 8, 16, etc)
 * Actually, this can be done by a simple test of the value (n & (n-1))
 * However, we're avoiding clever code
  */
static int power_of_2(unsigned n) {
    unsigned t;

    /* Step 't' through all the powers of 2 */
    for (t=1; t; t = 2*t) {
        if (t == n) return 1;  /* Yup, n is a power of 2 */
    }

    /* We went through all the powers of 2, didn't find a match */
    return 0;
}

/*
 * This is the scrypt hashing function; the point of this entire file
 */
int scrypt(const char *password, unsigned len_password,
           const char *salt, unsigned len_salt,
           unsigned r,
           unsigned N,
           unsigned p,
           unsigned char *output, unsigned dkLen)
{
    int status = 0;
    unsigned char *B_byte;  /* The intermediate value, in a 'series of 8-bit bytes' format */
    unsigned long *B;       /* The intermediate value, in a 'series of 32-bit words' format */
    unsigned i;

    /* Sanity check the parameters */
    if (p == 0 || N == 0 || r == 0) return 0;

    /*
     * scrypt allows non-powers of 2 for N, however, the internal Integrify
     * function becomes more complex.  While we could deal with it, it's
     * simpler to just disallow that case
     */
    if (!power_of_2(N)) return 0;

    /*
     * Allocate the value we'll use for the initial (that is, after we've first
     * run PBKDF2) hash
     */
    B_byte = (unsigned char*)malloc( p * r * 32 * 4 );
    B      = (unsigned long*)malloc( p * r * 32 * sizeof (unsigned long) );
    if (!B_byte || !B) {
        free(B_byte);   /* Can't allocate space */
        free(B);
        return 0;
    }

    /* Step 1: form B from the password */
    if (!pbkdf2_sha256(password, len_password,
                       salt, len_salt,
                       1,
                       B_byte, p * r * 32 * 4 )) {
        free(B_byte);   /* Hit intenral error */
        free(B);
        return 0;
    }

    /*
     * PBKDF2 gives a result as a string of bytes; reinterpret it as a string
     * of little-endian 32 bit words
     */
    for (i=0; i < p*r*32; i++) {
        B[i] = get_ulong_littleendian( &B_byte[ 4*i ] );
    }

    /* Step 2: run scryptROMix */
    for (i=0; i<p; i++) {
        if (!scryptROMix(r, B+32*i*r, N, B+32*i*r)) {
            free(B_byte);   /* Hit internal error */
            free(B);
            return status;
        }
    }

    /*
     * Ok, scryptROMix gave us an array of 32 bit words; convert it back into a
     * string of bytes (placing each word in 4 byte little-endian format)
     */
    for (i=0; i<32*p*r; i++) {
        put_ulong_littleendian( B_byte + 4*i, B[i] );
    }

    /* Step 3: run PBKDF2 to generate the actual output */
    if (!pbkdf2_sha256(password, len_password,
                       (const char *)B_byte, p * r * 32 * 4,
                       1,
                       output, dkLen)) {
        free(B_byte);   /* Hit internal error */
        free(B);
        return status;
    }

    status = 1;   /* We actually succeeded */
    free(B_byte);
    free(B);
    return status;
}
