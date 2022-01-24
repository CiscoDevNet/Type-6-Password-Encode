#if !defined(AES_H_)
#define AES_H_

/*
 * This is the definition of a portable AES implementation.  It's not
 * fast (we don't need speed).
 * This implementation only supports AES-128 encryption, because that's all
 * type 6 encryption (which is what we use this for) needs
 *
 * We also use the appropriate subset of the OpenSSL API as this API; that's so
 * that if someone wants to replacethis with the OpenSSL implementation, that's
 * easy
 */

#define AES_ENCRYPT     1
#define AES_BLOCK_SIZE 16

struct aes_key_st {
    unsigned char round_key[AES_BLOCK_SIZE * 11];  /* Only support 128 bit keys == 10 rounds */
};
typedef struct aes_key_st AES_KEY;

/* Expand an AES key.  Returns 0 on success */
int AES_set_encrypt_key(const unsigned char *userKey, int bits,
                        AES_KEY *key);

void AES_ecb_encrypt(const unsigned char *in, unsigned char *out,
                        const AES_KEY *key, int enc);

#endif /* ifdef(AES_H_) */
