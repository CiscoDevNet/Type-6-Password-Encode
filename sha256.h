#if !defined(SHA256_H_)
#define SHA256_H_

/* Length of a SHA256 hash */
#define SHA256_LEN		32

/* SHA256 context. */
typedef struct {
  unsigned long int state[8];        /* state; this is in the CPU native format */
  unsigned long count_low, count_high; /* number of bits processed so far */
  unsigned in_buffer;                /* number of bytes within the below */
                                     /* buffer */
  unsigned char buffer[64];          /* input buffer.  This is in byte vector format */
} SHA256_CTX;

void SHA256Init(SHA256_CTX *);  /* context */

void SHA256Update(SHA256_CTX *, /* context */
                  const void *, /* input block */ 
                  unsigned int);/* length of input block */

void SHA256Final(unsigned char *,
                 SHA256_CTX *);

#endif /* ifdef(SHA256_H_) */

