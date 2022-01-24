#if !defined(MD5_H_)
#define MD5_H_

/* Length of a MD5 hash */
#define MD5_LEN	                16

#define MD5_BLOCK_SIZE          64

/* MD5 context. */
typedef struct {
  unsigned long int state[4];        /* state; this is in the CPU native format */
  unsigned long count_low, count_high; /* number of bits processed so far */
  unsigned in_buffer;                /* number of bytes within the below */
                                     /* buffer */
  unsigned char buffer[MD5_BLOCK_SIZE]; /* input buffer.  This is in byte vector format */
} MD5_CTX;

void MD5Init(MD5_CTX *);  /* context */

void MD5Update(MD5_CTX *, /* context */
               const void *, /* input block */ 
               unsigned int);/* length of input block */

void MD5Final(unsigned char *, MD5_CTX *);

#endif /* ifdef(MD5_H_) */
