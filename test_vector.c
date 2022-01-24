#include <string.h>
#include <stdlib.h>
#include "test_vector.h"
#include "sha256.h"
#include "hmac_sha256.h"
#include "sha1.h"
#include "hmac_sha1.h"
#include "md5.h"
#include "aes.h"
#include "pbkdf2.h"
#include "scrypt.h"
#include "select_salt.h"
#include "ios_hash_password.h"
#include "ios_encrypt_password.h"
#include "convert_bitstring.h"

static int test_vector_sha256(const selftest_print *print_results);
static int test_vector_hmac_sha256(const selftest_print *print_results);
static int test_vector_sha1(const selftest_print *print_results);
static int test_vector_hmac_sha1(const selftest_print *print_results);
static int test_vector_md5(const selftest_print *print_results);
static int test_vector_aes128(const selftest_print *print_results);
static int test_vector_pbkdf2_1(const selftest_print *print_results);
static int test_vector_pbkdf2_2(const selftest_print *print_results);
static int test_vector_scrypt_1(const selftest_print *print_results);
static int test_vector_scrypt_2(const selftest_print *print_results);
static int test_vector_convert_bitstring(const selftest_print *print_results);
static int test_vector_generate_salt(const selftest_print *print_results);
static int test_vector_generate_type_6(const selftest_print *print_results);
static int test_vector_generate_type_8(const selftest_print *print_results);
static int test_vector_generate_type_9(const selftest_print *print_results);

/*
 * These are dummy print routines that we use if the caller didn't ask for any
 * output
 */
static void no_data(const char *title, const void *data, unsigned data_len) {
    ;
}
static void no_value(const char *title, int value) {
    ;
}
static void no_string(const char *title, const char *string) {
    ;
}

int do_test_vector( enum selftest test, const selftest_print *print_results ) {
    selftest_print print = { no_data, no_value, no_string };

    /*
     * If the caller hasn't given us the print functions, we skip on generating
     * any output.  By using dummy functions, the selftest functions don't need
     * to bother checking themselves
     */
    if (print_results && print_results->data) print.data = print_results->data;
    if (print_results && print_results->value) print.value = print_results->value;
    if (print_results && print_results->string) print.string = print_results->string;

    switch (test) {
    case SELFTEST_ALL: {
        /* Run all the tests; we pass only if every individual test passes */
        int overall_success = 1;
        for (test = SELFTEST_SHA256; test < SELFTEST_ALL; test++) {
            if (!do_test_vector( test, &print)) {
                overall_success = 0;
            }
        }
        return overall_success;
    }
    case SELFTEST_SHA256:
        return test_vector_sha256(&print);
    case SELFTEST_HMAC_SHA256:
        return test_vector_hmac_sha256(&print);
    case SELFTEST_SHA1:
        return test_vector_sha1(&print);
    case SELFTEST_HMAC_SHA1:
        return test_vector_hmac_sha1(&print);
    case SELFTEST_MD5:
        return test_vector_md5(&print);
    case SELFTEST_AES128:
        return test_vector_aes128(&print);
    case SELFTEST_PBKDF2_1:
        return test_vector_pbkdf2_1(&print);
    case SELFTEST_PBKDF2_2:
        return test_vector_pbkdf2_2(&print);
    case SELFTEST_SCRYPT_1:
        return test_vector_scrypt_1(&print);
    case SELFTEST_SCRYPT_2:
        return test_vector_scrypt_2(&print);
    case SELFTEST_CONVERT_BITSTRING:
        return test_vector_convert_bitstring(&print);
    case SELFTEST_GENERATE_SALT:
        return test_vector_generate_salt(&print);
    case SELFTEST_GENERATE_TYPE_6:
        return test_vector_generate_type_6(&print);
    case SELFTEST_GENERATE_TYPE_8:
        return test_vector_generate_type_8(&print);
    case SELFTEST_GENERATE_TYPE_9:
        return test_vector_generate_type_9(&print);
    default:
        return 0;  /* We didn't recognize this test */
    }
}

/* Run a SHA256 test vector */
static int test_vector_sha256(const selftest_print *print)
{
    /* This is the first SHA256 test vector from FIPS 180-2 */
    SHA256_CTX ctx;
    static unsigned char data[3] = { 0x61, 0x62, 0x63 }; /* "abc" in ASCII */
    unsigned data_len = 3;
    static const unsigned char exp_hash[SHA256_LEN] = {
        0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
        0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
        0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
        0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD
    };
    unsigned char actual_hash[SHA256_LEN] = { 0 };

    print->data( "Data to hash", data, data_len );
    print->data( "Expected hash", exp_hash, sizeof exp_hash );

    /* Compute the hash here */
    SHA256Init(&ctx);
    SHA256Update(&ctx, data, data_len);
    SHA256Final(actual_hash, &ctx);

    print->data( "Actual hash", actual_hash, sizeof actual_hash );

    return 0 == memcmp( exp_hash, actual_hash, SHA256_LEN );
}

/* Run an HMAC-SHA256 test vector */
static int test_vector_hmac_sha256(const selftest_print *print) {
    static const unsigned char test_key[32] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f };
    static const unsigned char test_data[9] = {
        0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x23, 0x32
        /* "Sample #2" in ASCII */
    };
    static const unsigned char exp_256mac[HMAC_SHA256_LEN] = {
        0x04, 0xBC, 0x7A, 0x23, 0xAA, 0xDC, 0xC0, 0xBF,
        0xA7, 0x99, 0x5B, 0xFF, 0x43, 0xE9, 0xC9, 0xF6,
        0xAF, 0x37, 0xA1, 0xB6, 0x84, 0xCD, 0x5F, 0x26,
        0xAA, 0xBA, 0x1D, 0x59, 0x67, 0x97, 0xA1, 0xDE
    };
    unsigned char act_256mac[HMAC_SHA256_LEN] = { 0 };

    print->data( "HMAC Key", test_key, sizeof test_key );
    print->data( "Data to MAC", test_data, sizeof test_data );
    print->data( "Expected MAC", exp_256mac, sizeof exp_256mac );

    /* Compute the hash here */
    hmac_sha256( test_key, sizeof test_key, test_data, sizeof test_data, act_256mac );

    print->data( "Actual MAC", act_256mac, sizeof act_256mac );

    return 0 == memcmp( exp_256mac, act_256mac, HMAC_SHA256_LEN );
}

/* Run a SHA1 test vector */
static int test_vector_sha1(const selftest_print *print)
{
    SHA1_CTX ctx;
    static unsigned char data[3] = { 0x61, 0x62, 0x63 }; /* "abc" in ASCII */
    unsigned data_len = 3;
    static const unsigned char exp_hash[SHA1_LEN] = {
        0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A,
        0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C,
         0x9C, 0xD0, 0xD8, 0x9D
    };
    unsigned char actual_hash[SHA1_LEN] = { 0 };

    print->data( "Data to hash", data, data_len );
    print->data( "Expected hash", exp_hash, sizeof exp_hash );

    /* Compute the hash here */
    SHA1Init(&ctx);
    SHA1Update(&ctx, data, data_len);
    SHA1Final(actual_hash, &ctx);

    print->data( "Actual hash", actual_hash, sizeof actual_hash );

    return 0 == memcmp( exp_hash, actual_hash, SHA1_LEN );
}

/* Run an HMAC-SHA1 test vector */
static int test_vector_hmac_sha1(const selftest_print *print) {
    static const unsigned char test_key[20] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        0x40, 0x41, 0x42, 0x43 };
    static const unsigned char test_data[9] = {
        0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x23, 0x32
        /* "Sample #2" in ASCII */
    };
    static unsigned char exp_mac[HMAC_SHA1_LEN] = {
        0x09, 0x22, 0xD3, 0x40, 0x5F, 0xAA, 0x3D, 0x19,
        0x4F, 0x82, 0xA4, 0x58, 0x30, 0x73, 0x7D, 0x5C,
        0xC6, 0xC7, 0x5D, 0x24 };
    unsigned char act_mac[HMAC_SHA1_LEN] = { 0 };

    print->data( "HMAC Key", test_key, sizeof test_key );
    print->data( "Data to MAC", test_data, sizeof test_data );
    print->data( "Expected MAC", exp_mac, sizeof exp_mac );

    /* Compute the hash here */
    hmac_sha1( test_key, sizeof test_key, test_data, sizeof test_data, act_mac );

    print->data( "Actual MAC", act_mac, sizeof act_mac );

    return 0 == memcmp( exp_mac, act_mac, HMAC_SHA1_LEN );
}

/* Run a MD5 test vector */
static int test_vector_md5(const selftest_print *print)
{
    MD5_CTX ctx;
    static unsigned char data[3] = { 0x61, 0x62, 0x63 }; /* "abc" in ASCII */
    unsigned data_len = 3;
    static const unsigned char exp_hash[MD5_LEN] = {
        0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
        0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72
    };
    unsigned char actual_hash[MD5_LEN] = { 0 };

    print->data( "Data to hash", data, data_len );
    print->data( "Expected hash", exp_hash, sizeof exp_hash );

    /* Compute the hash here */
    MD5Init(&ctx);
    MD5Update(&ctx, data, data_len);
    MD5Final(actual_hash, &ctx);

    print->data( "Actual hash", actual_hash, sizeof actual_hash );

    return 0 == memcmp( exp_hash, actual_hash, MD5_LEN );
}

/* Run an AES128 test vector */
static int test_vector_aes128(const selftest_print *print) {
    static const unsigned char test_key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

    static const unsigned char test_plaintext[AES_BLOCK_SIZE] = {
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 };

    static const unsigned char exp_ciphertext[AES_BLOCK_SIZE] = {
        0xF5, 0xD3, 0xD5, 0x85, 0x03, 0xB9, 0x69, 0x9D,
        0xE7, 0x85, 0x89, 0x5A, 0x96, 0xFD, 0xBA, 0xAF };

    AES_KEY expanded;
    unsigned char act_ciphertext[AES_BLOCK_SIZE];
    unsigned char *act_ciphertext_pointer;

    print->data( "AES Key", test_key, sizeof test_key );
    print->data( "Plaintext block", test_plaintext, sizeof test_plaintext );
    print->data( "Expected ciphertext", exp_ciphertext, sizeof exp_ciphertext );

    /* Do the actual encryption */
    act_ciphertext_pointer = NULL;
    if (0 == AES_set_encrypt_key(test_key, 128, &expanded)) {
        AES_ecb_encrypt(test_plaintext, act_ciphertext, &expanded, AES_ENCRYPT);
        act_ciphertext_pointer = act_ciphertext;
    }

    print->data( "Actual ciphertext", act_ciphertext_pointer, sizeof act_ciphertext );

    return act_ciphertext_pointer &&
           0 == memcmp( exp_ciphertext, act_ciphertext_pointer, AES_BLOCK_SIZE );
}

/*
 * This runs the short self-test of the PBKDF2 function
 */
static int test_vector_pbkdf2_1(const selftest_print *print) {
#define PBKDF2_1_HASH_LEN  32
#define PBKDF2_1_ITER    4096
    static const char password[8] = {
        0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64
        /* "password" in ASCII */
    };
    static const char salt[4] = {
        0x73, 0x61, 0x6c, 0x74
        /* "salt" in ASCII */
    };
    static const unsigned char exp_hash[PBKDF2_1_HASH_LEN] = {
        0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41,
        0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
        0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11,
        0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a
    };
    unsigned char act_hash[PBKDF2_1_HASH_LEN] = { 0 };
    unsigned char *act_hash_pointer = 0;

    print->data( "Password", password, sizeof password );
    print->data( "Salt", salt, sizeof salt );
    print->value( "Iterations", PBKDF2_1_ITER );
    print->data( "Expected Hash", exp_hash, sizeof exp_hash );

    /* Compute the hash here */
    if (pbkdf2_sha256(password, sizeof password,
                           salt, sizeof salt,
                           PBKDF2_1_ITER,
                           act_hash, PBKDF2_1_HASH_LEN)) {
        /* The function succeeded; we can use the buffer */
        act_hash_pointer = act_hash;
    }

    print->data( "Actual Hash", act_hash_pointer, PBKDF2_1_HASH_LEN );

    if (act_hash_pointer && 0 == memcmp( exp_hash, act_hash_pointer, PBKDF2_1_HASH_LEN )) {
        /* We suceeded */
        return 1;
    }
    return 0;
}

/*
 * This runs a longer self-test of the PBKDF2 function
 */
static int test_vector_pbkdf2_2(const selftest_print *print) {
#define PBKDF2_2_HASH_LEN  40
#define PBKDF2_2_ITER    4096
    static const char password[24] = {
        0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64,
        0x50, 0x41, 0x53, 0x53, 0x57, 0x4f, 0x52, 0x44,
        0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64

        /* "passwordPASSWORDpassword" in ASCII */
    };
    static const char salt[36] = {
        0x73, 0x61, 0x6c, 0x74, 0x53, 0x41, 0x4c, 0x54,
        0x73, 0x61, 0x6c, 0x74, 0x53, 0x41, 0x4c, 0x54,
        0x73, 0x61, 0x6c, 0x74, 0x53, 0x41, 0x4c, 0x54,
        0x73, 0x61, 0x6c, 0x74, 0x53, 0x41, 0x4c, 0x54,
        0x73, 0x61, 0x6c, 0x74
        /* "saltSALTsaltSALTsaltSALTsaltSALTsalt" in ASCII */
    };
    static const unsigned char exp_hash[PBKDF2_2_HASH_LEN] = {
        0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f,
        0x32, 0xd8, 0x14, 0xb8, 0x11, 0x6e, 0x84, 0xcf,
        0x2b, 0x17, 0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18,
        0x1c, 0x4e, 0x2a, 0x1f, 0xb8, 0xdd, 0x53, 0xe1,
        0xc6, 0x35, 0x51, 0x8c, 0x7d, 0xac, 0x47, 0xe9
    };
    unsigned char act_hash[PBKDF2_2_HASH_LEN] = { 0 };
    unsigned char *act_hash_pointer = 0;

    print->data( "Password", password, sizeof password );
    print->data( "Salt", salt, sizeof salt );
    print->value( "Iterations", PBKDF2_2_ITER );
    print->data( "Expected Hash", exp_hash, sizeof exp_hash );

    /* Compute the hash here */
    if (pbkdf2_sha256(password, sizeof password,
                           salt, sizeof salt,
                           PBKDF2_2_ITER,
                           act_hash, PBKDF2_2_HASH_LEN)) {
        /* The function succeeded; we can use the buffer */
        act_hash_pointer = act_hash;
    }

    print->data( "Actual Hash", act_hash_pointer, PBKDF2_2_HASH_LEN );

    if (act_hash_pointer && 0 == memcmp( exp_hash, act_hash_pointer, PBKDF2_2_HASH_LEN )) {
        /* We suceeded */
        return 1;
    }
    return 0;
}

/*
 * This runs the short self-test of the SCRYPT function
 * This is the first test vector from the Internet draft.  Yes, I agree, the
 * empty password and salt does look funny
 */
static int test_vector_scrypt_1(const selftest_print *print) {
#define SCRYPT_1_HASH_LEN  64
#define SCRYPT_1_N         16
#define SCRYPT_1_R          1
#define SCRYPT_1_P          1
    static const char *password = "";
        /* It's actually the null password */
    unsigned password_len = 0;
    static const char *salt = "";
        /* It's actually the null salt */
    unsigned salt_len = 0;
    static const unsigned char exp_hash[SCRYPT_1_HASH_LEN] = {
        0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20,
        0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a, 0x04, 0x97,
        0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8,
        0xdf, 0xdf, 0xfa, 0x3f, 0xed, 0xe2, 0x14, 0x42,
        0xfc, 0xd0, 0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8,
        0x32, 0x6a, 0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17,
        0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28,
        0xcf, 0x35, 0xe2, 0x0c, 0x38, 0xd1, 0x89, 0x06
    };
    unsigned char act_hash[SCRYPT_1_HASH_LEN] = { 0 };
    unsigned char *act_hash_pointer = 0;

    print->data( "Password", password, password_len );
    print->data( "Salt", salt, salt_len );
    print->value( "N", SCRYPT_1_N );
    print->value( "R", SCRYPT_1_R );
    print->value( "P", SCRYPT_1_P );
    print->data( "Expected Hash", exp_hash, sizeof exp_hash );

    /* Compute the hash here */
    if (scrypt(password, password_len,
               salt, salt_len,
               SCRYPT_1_R, SCRYPT_1_N, SCRYPT_1_P,
               act_hash, SCRYPT_1_HASH_LEN)) {
        /* The function succeeded; we can use the buffer */
        act_hash_pointer = act_hash;
    }

    print->data( "Actual Hash", act_hash_pointer, SCRYPT_1_HASH_LEN );

    if (act_hash_pointer && 0 == memcmp( exp_hash, act_hash_pointer, SCRYPT_1_HASH_LEN )) {
        /* We suceeded */
        return 1;
    }
    return 0;
}

/*
 * This runs the moderate self-test of the SCRYPT function
 * This is the second test vector from the Internet draft.
 */
static int test_vector_scrypt_2(const selftest_print *print) {
#define SCRYPT_2_HASH_LEN  64
#define SCRYPT_2_N       1024
#define SCRYPT_2_R          8
#define SCRYPT_2_P         16
    static const char password[8] = {
        0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64
        /* "password" in ASCII */
    };
    static const char salt[4] = { 
        0x4e, 0x61, 0x43, 0x6c
        /* "NaCl" in ASCII */
    };
    static const unsigned char exp_hash[SCRYPT_2_HASH_LEN] = {
        0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00,
        0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01, 0xe9, 0xfe,
        0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30,
        0xe7, 0x73, 0x76, 0x63, 0x4b, 0x37, 0x31, 0x62,
        0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88,
        0x6f, 0xf1, 0x09, 0x27, 0x9d, 0x98, 0x30, 0xda,
        0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d,
        0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40
    };
    unsigned char act_hash[SCRYPT_2_HASH_LEN] = { 0 };
    unsigned char *act_hash_pointer = 0;

    print->data( "Password", password, sizeof password );
    print->data( "Salt", salt, sizeof salt );
    print->value( "N", SCRYPT_2_N );
    print->value( "R", SCRYPT_2_R );
    print->value( "P", SCRYPT_2_P );
    print->data( "Expected Hash", exp_hash, sizeof exp_hash );

    /* Compute the hash here */
    if (scrypt(password, sizeof password,
               salt, sizeof salt,
               SCRYPT_2_R, SCRYPT_2_N, SCRYPT_2_P,
               act_hash, SCRYPT_2_HASH_LEN)) {
        /* The function succeeded; we can use the buffer */
        act_hash_pointer = act_hash;
    }

    print->data( "Actual Hash", act_hash_pointer, SCRYPT_2_HASH_LEN );

    if (act_hash_pointer && 0 == memcmp( exp_hash, act_hash_pointer, SCRYPT_2_HASH_LEN )) {
        /* We suceeded */
        return 1;
    }
    return 0;
}

/*
 * To test out the convert bitstring function, we try encoding a random-looking
 * bitstring, and seeing if it encodes to what we expect
 */
static int test_vector_convert_bitstring(const selftest_print *print) {
#define CONVERT_BITSTRING_INPUT_LEN 64
#define CONVERT_BITSTRING_OUTPUT_LEN (4 * CONVERT_BITSTRING_INPUT_LEN / 3 + 3 )
    static const unsigned char buffer[CONVERT_BITSTRING_INPUT_LEN] = {
        0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41,
        0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
        0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11,
        0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a,
        0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f,
        0x32, 0xd8, 0x14, 0xb8, 0x11, 0x6e, 0x84, 0xcf,
        0x2b, 0x17, 0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18,
        0x1c, 0x4e, 0x2a, 0x1f, 0xb8, 0xdd, 0x53, 0xe1
    };
    char output[CONVERT_BITSTRING_OUTPUT_LEN] = "";
    /* Note: the below is in the native CPU character set (which might not */
    /* be ASCII).  That's OK, because get_printable_hash produces output in */
    /* the native character CPU character set, so we'll being comparing */
    /* apples to apples below */
    const char *expected_output =
        "lSFspN86m24eIkqqV3lAXNMcYu./nYsF"
        "d7MsQueM2ocoX6bPmxAf9n9M39UFPcHD"
        "8lQoTfkM./UQHWcTiBpHsE";

    char *output_p;

    print->data( "Input", buffer, sizeof buffer );
    print->string( "Expected output", expected_output);
    
    if (get_printable_hash(buffer, sizeof buffer, output, sizeof output)) {
        output_p = output;
    }

    print->string( "Actual output", output_p );

    if (output_p && 0 == strcmp( expected_output, output_p )) {
        return 1;
    }

    return 0;
}

/*
 * This tries to test out the salt generation.  In contrast to the other tests
 * in this file, this isn't a known-answer test; instead it's a test to check
 * if the salts generated look reasonable (are the correct length, are
 * different each time)
 */
static int test_vector_generate_salt(const selftest_print *print) {
    char salt_a[ AUTOGEN_SALT_LENGTH+1 ];
    char salt_b[ AUTOGEN_SALT_LENGTH+1 ];
    char *salt_a_pointer = 0;
    char *salt_b_pointer = 0;
  
    /* Generate two salts in a row */ 
    salt_a_pointer = select_salt( salt_a, sizeof salt_a );
    salt_b_pointer = select_salt( salt_b, sizeof salt_b );

    /* List the salts we generated */
    print->string( "First salt", salt_a_pointer);
    print->string( "Second salt", salt_b_pointer);

    /* We pass if:
     * - We were successful in generating both salts
     * - They're both of the correct length
     * - They're not the same
     */
    if (salt_a_pointer && salt_b_pointer &&
        strlen(salt_a_pointer) == AUTOGEN_SALT_LENGTH &&
        strlen(salt_b_pointer) == AUTOGEN_SALT_LENGTH &&
        strcmp(salt_a_pointer, salt_b_pointer) != 0) {
        return 1;   /* Everything looks good */
    }

    return 0;   /* Oops, something wasn't right */
}

/*
 * This tries to test out the generation of type 6 passwords
 */
static int test_vector_generate_type_6(const selftest_print *print) {
    const char *password = "password";     /* This is the password to try to encode */
    const char *key = "cisco123";     /* This is the key we use */
    const char *salt = "NdUI^_YP[VEP";   /* The fixed salt we use */
    const char *exp_hash = "NdUI^_YP[VEPG[MT_bfTEFNZYFCYe\\R\\M";
                                           /* The hash value we expect */
    char *actual_hash;

    print->string( "Password", password );
    print->string( "Key", key );
    print->string( "Salt", salt );
    print->string( "Expected hash", exp_hash );

    actual_hash = ios_encrypt_password(6, key, password, salt, 0, 0);

    print->string( "Computed hash", actual_hash );

    if (actual_hash && 0 == strcmp( actual_hash, exp_hash )) {
        free(actual_hash);
        return 1;   /* We got it right */
    } else {
        free(actual_hash);
        return 0;   /* Oops, something was wrong */
    }
}

/*
 * This tries to test out the generation of type 8 passwords
 */
#define HASH_LENGTH 62   /* Our hashes are 62 bytes long (including the null terminator) */
static int test_vector_generate_type_8(const selftest_print *print) {
    const char *password = "cisco123";     /* This is the password to try to encode */
    const char *salt = "J5J/1K3e8gk974";   /* The fixed salt we use */
    const char *exp_hash = "$8$J5J/1K3e8gk974$HRezVpnMZOhOU2uxFTv.79S1U1PpMScizwXS3Z1Dx1s";
                                           /* The hash value we expect */
    char hash_buffer[ HASH_LENGTH ];
    char *actual_hash;

    print->string( "Password", password );
    print->string( "Salt", salt );
    print->string( "Expected hash", exp_hash );

    actual_hash = ios_hash_password(8, password, salt, hash_buffer, sizeof hash_buffer);

    print->string( "Computed hash", actual_hash );

    if (actual_hash && 0 == strcmp( actual_hash, exp_hash )) {
        return 1;   /* We got it right */
    } else 
        return 0;   /* Oops, something was wrong */
}

/*
 * This tries to test out the generation of type 9 passwords
 */
static int test_vector_generate_type_9(const selftest_print *print) {
    const char *password = "cisco123";     /* This is the password to try to encode */
    const char *salt = "ihSswXDbk0kaVK";   /* The fixed salt we use */
    const char *exp_hash = "$9$ihSswXDbk0kaVK$o.uyR2nMrWtjMkrQwBXUR5lVuVt/KzG23rmYvshODXI";
                                           /* The hash value we expect */
    char hash_buffer[ HASH_LENGTH ];
    char *actual_hash;

    print->string( "Password", password );
    print->string( "Salt", salt );
    print->string( "Expected hash", exp_hash );

    actual_hash = ios_hash_password(9, password, salt, hash_buffer, sizeof hash_buffer);

    print->string( "Computed hash", actual_hash );

    if (actual_hash && 0 == strcmp( actual_hash, exp_hash )) {
        return 1;   /* We got it right */
    } else 
        return 0;   /* Oops, something was wrong */
}
