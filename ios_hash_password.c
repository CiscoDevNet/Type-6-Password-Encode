/*
 * This routine does the heavy lifting for generating an IOS hash
 *
 * It is isolated so that a customer might be able to call this directly
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "ios_hash_password.h"
#include "select_salt.h"
#include "pbkdf2.h"
#include "scrypt.h"
#include "convert_bitstring.h"

static int validate_salt(const char *s);

#define HASH_LEN 32        /* We generate 256 bit (32 byte) hashes */
#define ENCODED_HASH_LEN (4 * HASH_LEN / 3 + 2) /* This is how big the hash */
                           /* is after we convert it into ASCII */

#define PBKDF2_ITERATIONS 20000  /* Type 8 uses 20,000 iterations */
#define SCRYPT_N          16384  /* Type 9 uses 16,384 iterations */
#define SCRYPT_R          1      /* Type 9 uses 1 for its internal */
#define SCRYPT_P          1      /* R and P parameters */

/*
 * This is the function to generate the IOS hashed password
 */
char *ios_hash_password(int type, const char *password, const char *salt,
                        char *buffer, unsigned buffer_len)
{
    unsigned char raw_hash[ HASH_LEN ];
    char encoded_hash[ ENCODED_HASH_LEN ];
    char salt_buffer[ AUTOGEN_SALT_LENGTH+1 ];
    unsigned full_hash_length;

    if (!salt) {
        /* If we weren't give a salt, we pick a value */
        salt = select_salt( salt_buffer, sizeof salt_buffer );
        if (!salt) return 0;   /* Error */
    }

    if (!validate_salt(salt)) {
        /* Oops, the salt we were given wasn't valid */
        return 0;
    }

    /* Ok, compute the hash */
    switch (type) {
    case 8:
        if (!pbkdf2_sha256(password, strlen(password),
               salt, strlen(salt),
               PBKDF2_ITERATIONS,
               raw_hash, HASH_LEN)) {
            return 0; /* Oops, pbkdf2 failed */
        }
        break;
    case 9:
        if (!scrypt(password, strlen(password),
               salt, strlen(salt),
               SCRYPT_R, SCRYPT_N, SCRYPT_P,
               raw_hash, HASH_LEN)) {
            return 0; /* Oops, scrypt failed */
        }
        break;
    default:
        return 0; /* Oops, unknown hash */
    }

    /* Convert the hash into a printable form */
    if (!get_printable_hash(raw_hash, HASH_LEN, encoded_hash, sizeof encoded_hash )) {
        return 0; /* Oops, internal buffer overflow (should never happen) */
    }

    /*
     * Ok, we have all the intermediate components; build up the hash
     */

    /* This is how much space the full hash will take, including the null terminator */
    /* Remember, the format is "$x$salt$hash" */
    full_hash_length = 1 + 1 + 1 + strlen(salt) + 1 + strlen(encoded_hash) + 1;

    if (!buffer) {
        /* We weren't given a buffer, malloc one */
        buffer_len = full_hash_length;
        buffer = (char *)malloc(buffer_len);
        if (!buffer) {
            return 0;  /* Oops, can't allocate the buffer */
        }
    } else {
        /* We were given a buffer, make sure it's big enough */
        if (buffer_len < full_hash_length) {
            return 0;   /* Oops, won't fit */
        }
    }

    /*
     * Ok, we have a buffer that we know is large enough, and all the various
     * components; assemble the hash.
     * Again, the use of sprintf is safe; we checked the length above
     * I'd use snprintf, but that's not in C89
     */
    sprintf( buffer, "$%c$%s$%s", type + '0', salt, encoded_hash );

    /* And that's all folks */
    return buffer;
}

/*
 * This sanity checks a salt value, and returns 1 if it is usable
 * Currently, the restriction can be summarized as 'the salt consists of
 * printable characters other than space and $'$
 *  
 * characters'; if it did, it'd confuse the hash parsing logic within IOS
 */
static int validate_salt(const char *s) {
    unsigned i;

    for (i=0; s[i]; i++) {
        if (s[i] == '$' || !isgraph((unsigned char)s[i])) {
            /* Oops, '$' characters are not allowed */
            return 0;
        }
    }

    return 1;
}

unsigned ios_hash_passwordlen(int type, const char *salt) {
    unsigned salt_len, hash_len;

    if (salt) {
        /* We were given a salt; we'll copy it into the hash exactly as is */
        salt_len = strlen(salt);
    } else {
        /* We pick the salt ourselves; use the length of salts we autogen */
        salt_len = AUTOGEN_SALT_LENGTH;
    }

    hash_len = HASH_LEN;  /* All hash types has the same hash length */

    /* Ok, return the length */
    return 1 + 1 + 1 + salt_len + 1 + get_printable_hash_output_len(hash_len);
        /* get_printable_hash_output_len includes the null terminator */
}
