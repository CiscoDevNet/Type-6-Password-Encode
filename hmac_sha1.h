#if !defined( HMAC_SHA1_H_ )
#define HMAC_SHA1_H_

#define HMAC_SHA1_LEN 20

void hmac_sha1( const void *key, unsigned len_key,
                const void *data, unsigned len_data,
                unsigned char *output );

#endif /* HMAC_SHA1_H_ */
