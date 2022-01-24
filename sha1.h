#if !defined(SHA1_H_)
#define SHA1_H_

/* Length of a SHA1 hash */
#define SHA1_LEN		20

#define SHA1_BLOCK_SIZE         64

/* SHA1 context. */
typedef struct {
  unsigned long int state[5];        /* state; this is in the CPU native format */
  unsigned long count_low, count_high; /* number of bits processed so far */
  unsigned in_buffer;                /* number of bytes within the below */
                                     /* buffer */
  unsigned char buffer[SHA1_BLOCK_SIZE]; /* input buffer.  This is in byte vector format */
} SHA1_CTX;

void SHA1Init(SHA1_CTX *);  /* context */

void SHA1Update(SHA1_CTX *, /* context */
                const void *, /* input block */ 
                unsigned int);/* length of input block */

void SHA1Final(unsigned char *,
               SHA1_CTX *);

#endif /* ifdef(SHA1_H_) */

