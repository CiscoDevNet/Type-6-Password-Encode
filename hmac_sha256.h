#if !defined( HMAC_SHA256_H_ )
#define HMAC_SHA256_H_

#define HMAC_SHA256_LEN 32

void hmac_sha256( const void *key, unsigned len_key,
                  const void *data, unsigned len_data,
                  unsigned char *output );

#endif /* HMAC_SHA256_H_ */
