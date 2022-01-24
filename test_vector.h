#if !defined( TEST_VECTOR_H_ )
#define TEST_VECTOR_H_

/*
 * This is the internal to our internal test vector logic
 * It is designed to run sanity checks on the various crypto components
 *
 * It is called by:
 *     int passed = do_test_vector( SELFTEST_FOO, print_results );
 * where:
 *     SELFTEST_FOO indicates the specific primitive to test (SELFTEST_ALL for
 *         everything)
 *     print_results is a function to print intermediate results; if you are
 *         not interested, you can pass NULL
 * If the test passed, this returns nonzero
 *
 * This has been defined this way, so that, if a customer wishes, he can call
 * this to run a general sanity test
 */
enum selftest {
    SELFTEST_SHA256,     /* Our SHA256 implementation */
    SELFTEST_HMAC_SHA256, /* Our HMAC-SHA256 implementation */
    SELFTEST_SHA1,       /* Our SHA1 implementation */
    SELFTEST_HMAC_SHA1,  /* Our HMAC-SHA1 implementation */
    SELFTEST_MD5,        /* Our MD5 implementation */
    SELFTEST_AES128,     /* Our AES128 implementation */
    SELFTEST_PBKDF2_1,   /* Our PBKDF2 implementation (first test vector) */
    SELFTEST_PBKDF2_2,   /* Our PBKDF2 implementation (second test vector) */
    SELFTEST_SCRYPT_1,   /* Our scrypt implementation (first test vector) */
    SELFTEST_SCRYPT_2,   /* Our scrypt implementation (second test vector) */
    SELFTEST_CONVERT_BITSTRING, /* The convert_bitstring function */
    SELFTEST_GENERATE_SALT, /* Our salt generation */
    SELFTEST_GENERATE_TYPE_6, /* Test generating type 6 passwords */
    SELFTEST_GENERATE_TYPE_8, /* Test generating type 8 passwords */
    SELFTEST_GENERATE_TYPE_9, /* Test generating type 9 passwords */
    SELFTEST_ALL,      /* Test everything */
};

/*
 * This are functions that prints out intermediate results (be those be blocks
 * of raw data, integers or text.  Parameters:
 * title -- The human-readable title for the data being printed out
 * data -- The actual data (or NULL if we got an error generating the data)
 * data_len -- The length of the above data
 * value -- The value to print out
 * string -- The human-readable text to print out
 */
typedef void (*selftest_print_data)(const char *title,
                                 const void *data, unsigned data_len);
typedef void (*selftest_print_value)(const char *title, int value);
typedef void (*selftest_print_string)(const char *title, const char *string);

/*
 * This is a structure to hold the three together; it's here mainly so we don't
 * have to pass all three individually
 */
typedef struct selftest_print {
    selftest_print_data data;
    selftest_print_value value;
    selftest_print_string string;
} selftest_print;
int do_test_vector( enum selftest, const selftest_print *print_results );

#endif /* TEST_VECTOR_H_ */
