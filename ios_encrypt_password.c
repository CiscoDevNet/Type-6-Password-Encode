/*
 * This routine does the heavy lifting for encrypting an IOS password
 *
 * It is isolated so that a customer might be able to call this directly
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "ios_encrypt_password.h"
#include "select_salt.h"
#include "aes.h"
#include "md5.h"
#include "hmac_sha1.h"
#include "convert_bitstring.h"

#define TYPE6_SALT_LEN 8
#define TYPE6_ENCODED_SALT_LEN 12  /* 3 * 8 / 2 */
#define TYPE6_MAC_LEN  4

/*
 * This is the function to encrypt an IOS password
 */
char *ios_encrypt_password(int type, const char *master_key,
                           const char *password, const char *salt,
                           char *buffer, unsigned buffer_len)
{
    AES_KEY expanded_key;
    size_t temp_buffer_len;
    unsigned char *temp_buffer, *temp_output;
    unsigned char ka[AES_BLOCK_SIZE], ke[AES_BLOCK_SIZE];
    unsigned char mysalt[TYPE6_SALT_LEN];
    unsigned i;
    unsigned char temp[AES_BLOCK_SIZE];
    unsigned pass_len = strlen(password);
    unsigned unarmored_length, armored_length;
    int did_malloc = 0;

    /* We support only type 6 password encryption */ 
    if (type != 6) return NULL;

    /* Generate the salt */
    if (salt) {
        /* Convert the salt that the user gave us into our internal format */
        if (strlen(salt) != TYPE6_ENCODED_SALT_LEN) {
            printf( "Error: salts for type 6 passwords must be exactly %d characters long\n", TYPE6_ENCODED_SALT_LEN );
            return NULL;
        } else {
           if (!decode_printable_hash_type_6(salt, strlen(salt), mysalt, sizeof mysalt )) {
               printf( "Error: illegal salt for type 6 password\n" );
               return NULL;
           }
        }
    } else {
        /* No salt provided; pick a random one */
        get_random_bytes(mysalt, TYPE6_SALT_LEN);
    }

    /* Convert the master key into an 128 bit form */
    {
        MD5_CTX ctx;
        unsigned char aes_master_key[16];
        MD5Init(&ctx);
        MD5Update(&ctx, master_key, strlen(master_key));
        MD5Final(aes_master_key, &ctx);

        if (0 != AES_set_encrypt_key(aes_master_key, 128, &expanded_key)) {
            return 0;
        }
    }

    /* Produce encryption and integrity keys */
    memset(temp, 0, AES_BLOCK_SIZE);
    memcpy(temp, mysalt, TYPE6_SALT_LEN);
    AES_ecb_encrypt(temp, ka, &expanded_key, AES_ENCRYPT);
    temp[15] = 0x01;
    AES_ecb_encrypt(temp, ke, &expanded_key, AES_ENCRYPT);

    /* Initialize crypto primitives */
    if (0 != AES_set_encrypt_key(ke, 128, &expanded_key)) {
        return 0;
    }

    temp_buffer_len = TYPE6_SALT_LEN + pass_len + 1 + TYPE6_MAC_LEN;
    temp_buffer = temp_output = malloc(temp_buffer_len);
    if (!temp_buffer) return 0;

    /* Produce output -- salt first */
    memcpy(temp_output, mysalt, TYPE6_SALT_LEN);
    temp_output += TYPE6_SALT_LEN;

    /* Next -- produce cipher text output */
    for (i=0; i<=pass_len; i++) {
        unsigned char c;
        if ((i%16) == 0) {
            memset(temp, 0, 16);
            temp[3] = i/16;
            AES_ecb_encrypt(temp, temp, &expanded_key, AES_ENCRYPT);
        }
        c = password[i] ^ temp[ i%16 ];
        *temp_output++ = c;
    }

    /* Lastly, append the MAC */
    {
        unsigned char mac[HMAC_SHA1_LEN];
        hmac_sha1(ka, sizeof ka, temp_output-pass_len-1, pass_len+1, mac);
        memcpy(temp_output, mac, TYPE6_MAC_LEN);
        temp_output += TYPE6_MAC_LEN;
    }
    unarmored_length = temp_buffer_len;
    armored_length = get_printable_hash_output_type_6_len(unarmored_length);

    /* Get the output buffer */
    if (!buffer) {
        /* We weren't given a buffer, malloc one */
        buffer_len = armored_length;
        buffer = (char *)malloc(buffer_len);
        if (!buffer) {
            free(temp_buffer);
            return 0;  /* Oops, can't allocate the buffer */
        }
        did_malloc = 1;
    } else {
        /* We were given a buffer, make sure it's big enough */
        if (buffer_len < armored_length) {
            free(temp_buffer);
            return 0;   /* Oops, won't fit */
        }
    }


    /* Now, ASCII-armor the encryption */
    if (!get_printable_hash_type_6(temp_buffer, unarmored_length, buffer, buffer_len )) {
        free(temp_buffer);
        if (did_malloc) free(buffer);
        return 0; /* Oops, internal buffer overflow (should never happen) */
    }

    /* Got it! */
    free(temp_buffer);

    return buffer;
}
