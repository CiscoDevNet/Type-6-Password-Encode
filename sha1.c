/*
 * SHA-1
 */

#include <string.h>
#include "sha1.h"
#include "endian.h"

#define SHA1_FINALCOUNT_SIZE  8
#define M 0xffffffff   /* Lets keep things to 32 bits */

#define rol(value, bits) ((((value) << (bits)) | ((value) >> (32 - (bits)))) & M)

/*
 * (R0+R1), R2, R3, R4 are the different operations (rounds) used in SHA1
 */
#define R0(v,w,x,y,z,i) z = (z + (((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5))) & M;w=rol(w,30);
#define R1(v,w,x,y,z,i) z = (z + ((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5)) & M;w=rol(w,30);
#define R2(v,w,x,y,z,i) z = (z + ((w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5))) & M;w=rol(w,30);
#define R3(v,w,x,y,z,i) z = (z + (((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5)) & M;w=rol(w,30);
#define R4(v,w,x,y,z,i) z = (z + (w^x^y)+blk(i)+0xCA62C1D6+rol(v,5)) & M;w=rol(w,30);

#define blk0(i) block[i]
#define blk(i) (block[i&15] = rol((block[(i+13)&15]^block[(i+8)&15]^block[(i+2)&15]^block[i&15]) & M,1))

/*
 * Hash a single 512-bit block. This is the core of the algorithm.
 */
static void sha1_compress(unsigned long *state, unsigned char *buffer)
{
    int i;
    unsigned long a, b, c, d, e;
    unsigned long block[16];

    for (i = 0; i<SHA1_BLOCK_SIZE/4; i++) {
        block[i] = get_ulong_bigendian( &buffer[4*i] );
    }

    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

    /* Add the working vars back into context.state[] */
    state[0] = (state[0] + a) & M;
    state[1] = (state[1] + b) & M;
    state[2] = (state[2] + c) & M;
    state[3] = (state[3] + d) & M;
    state[4] = (state[4] + e) & M;
}

void SHA1Init (SHA1_CTX *ctx)
{
    ctx->count_low = 0;
    ctx->count_high = 0;
    ctx->in_buffer = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
}

void SHA1Update (SHA1_CTX *ctx, const void *src, unsigned int count)
{
    unsigned long new_count = (ctx->count_low + (count << 3)) & M;
    if (new_count < ctx->count_low) {
        ctx->count_high += 1;
    }
    ctx->count_low = new_count;

    while (count) {
        unsigned int this_step = 64 - ctx->in_buffer;
        if (this_step > count) this_step = count;
        memcpy( ctx->buffer + ctx->in_buffer, src, this_step);

        if (this_step + ctx->in_buffer < 64) {
            ctx->in_buffer += this_step;
            break;
        }

        src = (const unsigned char *)src + this_step;
        count -= this_step;
        ctx->in_buffer = 0;

        sha1_compress( ctx->state, ctx->buffer );
    }
}

/*
 * Add padding and return the message digest.
 */
void SHA1Final (unsigned char *digest, SHA1_CTX *ctx)
{
    unsigned int i;
    unsigned char finalcount[SHA1_FINALCOUNT_SIZE];

    put_ulong_bigendian( &finalcount[0], ctx->count_high );
    put_ulong_bigendian( &finalcount[4], ctx->count_low );

    SHA1Update(ctx, "\200", 1);

    if (ctx->in_buffer > 56) {
        SHA1Update(ctx, "\0\0\0\0\0\0\0\0", 8);
    }
    memset( ctx->buffer + ctx->in_buffer, 0, 56 - ctx->in_buffer );
    ctx->in_buffer = 56;
    SHA1Update(ctx, finalcount, SHA1_FINALCOUNT_SIZE);  /* Should cause a sha1_compress() */

    /*
     * The final state is an array of unsigned long's; place them as a series
     * of bigendian 4-byte words onto the output
     */ 
    for (i=0; i<5; i++) {
        put_ulong_bigendian( digest + 4*i, ctx->state[i] );
    }
}
