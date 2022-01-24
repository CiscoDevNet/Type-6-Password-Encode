/*
 * This is a program this is designed to encode passwords using the
 * IOS type 6, 8 and type 9 password hash methods.
 *
 * How this program is used:
 *  epp -type <value> -password <password> [-salt <salt>]
 * This computes the value of the password hash, and outputs that to the
 * standard output (exits with an EXIT_SUCCESS).
 *
 * - value: this is the hash type.  The supported hash types are:
 *   6 (or "aes"): this is the IOS type 6 encryption type
 *   8 (or "sha-256"): this is the IOS type 8 hash type
 *   9 (or "scrypt"): this is the IOS type 9 hash type
 * - password: this is the password to hash
 * - salt: this is the salt to use.  If one is not provided, ths will select a
 *   random salt
 * -k: this is the master key to use.  Requird for type 6
 *
 * On failure, this prints nothing to the standard output.  Instead, it
 * generates a human readable error on the standard error output, and
 * exits with an EXIT_FAILURE.
 *
 * You can also run the program with:
 *  epp -verify
 * This will run a set of sanity tests on the internal routines
 *
 *
 * Goals of this program:
 * - It tries to be maximally portable, because a customer may want to
 *   integrate this program (or parts of it) with his management system, and we
 *   have no idea what that might be.
 *   We try to make this a strictly conforming C89 program; however, we do fall
 *   short of the goal in the following aspects:
 *   - We leave in the restriction that the computer uses ASCII; that's because
 *     this takes an ASCII password from the user, and hashes it.  It's hard to
 *     allow someone to use a non-ASCII character set, and still allow all
 *     printable ASCII characters.  It might work with a Unicode-based C
 *     compiler; I haven't tried it
 *   - We assume that we can malloc a reasonable amount of memory (quite
 *     modest amounts of type 8, about two megabytes for type 9). If you can't
 *     live with that, you probably should get a real computer
 *   - The salt generation logic is merely conforming (meaning that it won't
 *     necessarily work exactly the same way on all implementations); it'll
 *     generate value salts everywhere, however, the salts it generates may
 *     be different on different implementations.  Given that reproducibility
 *     is not a goal of our salt generation logic, this was deemed acceptable
 *
 *   We have C89 strict conformance as a goal because virtually every computer
 *   has a C89 compiler somewhere, and most serious computer languages have a
 *   provision for making a call into a C89 routine; hence if the customer
 *   decides to link this in with their manangement application, we have a good
 *   chance of reducing the effort required.
 *
 * - It ought to be clear what the program is doing.  We're giving this to
 *   customers; we want to give people confidence in what we're doing, and they
 *   may need to adapt this for their own requirements.  Hence, transparency is
 *   a Good Thing; we consciously try to avoid clever (hard to understand) code
 *
 * A nongoal is performance.  Now, we don't go out of our way to make things
 * inefficient, however if there is a conflict between performance and either
 * of the other two goals, the other two goals win.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_vector.h"
#include "ios_hash_password.h"
#include "ios_encrypt_password.h"

static void usage(char *program_name);
static int do_verify(void);

int main(int argc, char **argv) {
    char *program_name;
    char *salt = 0;
    char *password = 0;
    char *master_key = 0;
    int verify = 0; /* If set, we run internal crypto test vectors */
    int type = 0;  /* 6 -> user asked for type 6; 8 -> user asked for type 8 */
                   /* 9 -> user asked for type 9 */
    int i;
    char *hash;  /* The hash output, including the $<type>$ boilerplate */
    char *failure_message;

    if (argv[0] == 0 || argv[0][0] == 0)
        program_name = "epp";  /* If the program name is not available, call ourselves epp */
    else
        program_name = argv[0];

    /*
     * First thing we do: argument parsing
     * getopt would be nice, however that's not included in the C89 standard
     * library; hence we do it the long way
     */
    if (argc <= 1) {
        fprintf( stderr, "This program takes a password, and converts it into\n"
                         "a type 8 and type 9 IOS hashed password\n" );
        usage(program_name);
        return EXIT_FAILURE;
    }
    for (i=1; i<argc; ) {
        if (0 == strcmp( argv[i], "-type" )) {
            if (type != 0) {
                fprintf( stderr, "Error: -type specified twice\n" );
                return EXIT_FAILURE;
            }
            if (i+1 < argc && (0 == strcmp( argv[i+1], "6" ) || 0 == strcmp( argv[i+1], "aes"))) {
                type = 6;
            } else if (i+1 < argc && (0 == strcmp( argv[i+1], "8" ) || 0 == strcmp( argv[i+1], "sha-256"))) {
                type = 8;
            } else if (i+1 < argc && (0 == strcmp( argv[i+1], "9") || 0 == strcmp( argv[i+1], "scrypt"))) {
                type = 9;
            } else {
                fprintf( stderr, "Error: illegal hash type %s\n", i+1 >= argc ? "[none]" : argv[i+1] );
                fprintf( stderr, "Legal values: 6, aes, 8, sha-256, 9, scrypt\n" );
                return EXIT_FAILURE;
            }
            i += 2;
       } else if (0 == strcmp( argv[i], "-salt" )) {
            if (salt != 0) {
                fprintf( stderr, "Error: -salt specified twice\n" );
                return EXIT_FAILURE;
            }
            if (i+1 >= argc) {
                fprintf( stderr, "Error: no salt specified\n" );
                return EXIT_FAILURE;
            }
            salt = argv[i+1];
            i += 2;
       } else if (0 == strcmp( argv[i], "-password" )) {
            if (password != 0) {
                fprintf( stderr, "Error: -password specified twice\n" );
                return EXIT_FAILURE;
            }
            if (i+1 >= argc) {
                fprintf( stderr, "Error: no password specified\n" );
                return EXIT_FAILURE;
            }
            password = argv[i+1];
            i += 2;
       } else if (0 == strcmp( argv[i], "-key" )) {
            if (master_key != 0) {
                fprintf( stderr, "Error: -key specified twice\n" );
                return EXIT_FAILURE;
            }
            if (i+1 >= argc) {
                fprintf( stderr, "Error: no key specified\n" );
                return EXIT_FAILURE;
            }
            master_key = argv[i+1];
            i += 2;
       } else if (0 == strcmp( argv[i], "-verify" )) {
            verify = 1;
            i += 1;
       } else {
            fprintf( stderr, "Error: unexpected arguement %s\n", argv[i] );
            usage(program_name);
            return EXIT_FAILURE;
       }
    }

    /* Make sure we got a set of arguments that make sense */
    if (verify) {
        if (type || password || salt || master_key) {
            fprintf( stderr, "Error: -verify and %s specified\n",
                type ? "-type" : password ? "-password" : salt ? "-salt" : "-key" );
            usage(program_name);
            return EXIT_FAILURE;
        }
    } else {
        if (type == 0) {
            fprintf( stderr, "Error: no -type specified\n" );
            usage(program_name);
            return EXIT_FAILURE;
        }
        if (password == 0) {
            fprintf( stderr, "Error: no -password specified\n" );
            usage(program_name);
            return EXIT_FAILURE;
        }
        if (type == 6) {
            if (master_key == 0) {
                fprintf( stderr, "Error: no -key specified; required for type 6\n" );
                usage(program_name);
                return EXIT_FAILURE;
            }
        } else {
            if (master_key != 0) {
                fprintf( stderr, "Error: -key specified; not used for type %d\n", type );
                usage(program_name);
                return EXIT_FAILURE;
            }
        }
    }

    if (verify) {
        /* We were asked to run our internal test vectors */
        return do_verify();
    }

    /*
     * Generate the hash.  Yeah, that's pretty straight-forward; the logic for
     * hashing and encoding the hash (and generating the IV, if necessary) is
     * in ios_hash_password; that's so a customer application can just call
     * ios_hash_password, should the customer find that appropriate.
     */
    if (type == 6) {
        hash = ios_encrypt_password( type, master_key, password, salt, 0, 0 );
        failure_message = "Error encrypting password";
    } else {
        hash = ios_hash_password( type, password, salt, 0, 0 );
        failure_message = "Error generating hash";
    }
    if (!hash) {
        fprintf( stderr, "%s\n", failure_message );
        return EXIT_FAILURE;
    }

    /* Output the hash. */
    printf( "%s\n", hash );

    /* We asked ios_hash_password to malloc the space; we need to free it */
    free(hash);

    return EXIT_SUCCESS;
}

static void usage(char *program_name) {
    fprintf( stderr, "Usage:\n" );
    fprintf( stderr, " %s -type 6 -key k -salt s -password foo\n", program_name );
    fprintf( stderr, "    Generates the type 6 password using the master key k, salt s and the\n"
                     "    password foo\n" );
    fprintf( stderr, " %s -type 8 -salt s -password foo\n", program_name );
    fprintf( stderr, "    Generates the type 8 password using the salt s and the password foo\n" );
    fprintf( stderr, " %s -type 9 -password foo\n", program_name );
    fprintf( stderr, "    Generates the type 9 password for the password foo using a random salt\n" );
    fprintf( stderr, " %s -verify\n", program_name );
    fprintf( stderr, "    Runs test vectors on the internal crypto\n" );
}

#define DATA_PER_ROW 16  /* List data in rows of 16 bytes each */
static void print_data(const char *title, const void *data, unsigned data_len) {
    const char *p;
    unsigned i;
    printf( "%20.20s : ", title );
    /* Caller will signify internal failure by passing NULL data */
    if (!data) { printf( "FAILED\n" ); return; }
    p = data;
    for (i=0; i<data_len; i++) {
        if (i && (i%DATA_PER_ROW)== 0) {
            printf( "\n%20.20s   ", "" );
        } else if (i) {
            printf( " " );
        }
        printf( "%02x", p[i] & 0xff );
    }
    printf( "\n" );
}

static void print_value(const char *title, int value) {
    printf( "%20.20s : %d\n", title, value );
}

#define CHAR_PER_ROW 48 /* List characters in rows of 48 each */
static void print_string(const char *title, const char *p) {
    printf( "%20.20s : ", title );
    unsigned i;
    /* Caller will signify internal failure by passing NULL data */
    if (!p) { printf( "FAILED\n" ); return; }
    for (i=0; p[i]; i++) {
        if (i && (i%CHAR_PER_ROW)== 0) {
            printf( "\n%20.20s   ", "" );
        }
        printf( "%c", p[i] );
    }
    printf( "\n" );
}

static void print_test_result(int test_result) {
    char *result_name;

    if (test_result != 0) {  /* Nonzero means success */
        result_name = "Success";
    } else {
        result_name = "FAILURE";
    }

    print_string( "Test result", result_name );
}

/*
 * This runs all our test vectors, and prints intermediate results to the user
 * It returns EXIT_SUCCESS if everything passed, EXIT_FAILURE is something failed
 */
static int do_verify(void) {
    int overall_result = EXIT_SUCCESS;
    int test_result;
    static struct selftest_print print_results = {
        print_data,
        print_value,
        print_string
    };

    /* Test SHA-256 */
    printf( "Testing SHA-256:\n" );
    test_result = do_test_vector( SELFTEST_SHA256, &print_results );
    print_test_result(test_result);
    if (!test_result) overall_result = EXIT_FAILURE;
    printf( "\n" );

    /* Test HMAC-SHA-256 */
    printf( "Testing HMAC-SHA-256:\n" );
    test_result = do_test_vector( SELFTEST_HMAC_SHA256, &print_results );
    print_test_result(test_result);
    if (!test_result) overall_result = EXIT_FAILURE;
    printf( "\n" );

    /* Test SHA-1 */
    printf( "Testing SHA-1:\n" );
    test_result = do_test_vector( SELFTEST_SHA1, &print_results );
    print_test_result(test_result);
    if (!test_result) overall_result = EXIT_FAILURE;
    printf( "\n" );

    /* Test HMAC-SHA-1 */
    printf( "Testing HMAC-SHA1:\n" );
    test_result = do_test_vector( SELFTEST_HMAC_SHA1, &print_results );
    print_test_result(test_result);
    if (!test_result) overall_result = EXIT_FAILURE;
    printf( "\n" );

    /* Test MD5 */
    printf( "Testing MD5:\n" );
    test_result = do_test_vector( SELFTEST_MD5, &print_results );
    print_test_result(test_result);
    if (!test_result) overall_result = EXIT_FAILURE;
    printf( "\n" );

    /* Test AES-128 */
    printf( "Testing AES-128:\n" );
    test_result = do_test_vector( SELFTEST_AES128, &print_results );
    print_test_result(test_result);
    if (!test_result) overall_result = EXIT_FAILURE;
    printf( "\n" );

    /* Test PBKDF2 */
    printf( "Testing PBKDF2 (first test vector):\n" );
    test_result = do_test_vector( SELFTEST_PBKDF2_1, &print_results );
    print_test_result(test_result);
    if (!test_result) overall_result = EXIT_FAILURE;
    printf( "\n" );

    /* Test PBKDF2 */
    printf( "Testing PBKDF2 (second test vector):\n" );
    test_result = do_test_vector( SELFTEST_PBKDF2_2, &print_results );
    print_test_result(test_result);
    if (!test_result) overall_result = EXIT_FAILURE;
    printf( "\n" );

    /* Test SCRYPT */
    printf( "Testing SCRYPT (first test vector):\n" );
    test_result = do_test_vector( SELFTEST_SCRYPT_1, &print_results );
    print_test_result(test_result);
    if (!test_result) overall_result = EXIT_FAILURE;
    printf( "\n" );

    /* Test SCRYPT */
    printf( "Testing SCRYPT (second test vector):\n" );
    test_result = do_test_vector( SELFTEST_SCRYPT_2, &print_results );
    print_test_result(test_result);
    if (!test_result) overall_result = EXIT_FAILURE;
    printf( "\n" );
 
    /* Test convert_bitstring */
    printf( "Testing convert_bitstring:\n" );
    test_result = do_test_vector( SELFTEST_CONVERT_BITSTRING, &print_results );
    print_test_result(test_result);
    if (!test_result) overall_result = EXIT_FAILURE;
    printf( "\n" );
 
    /* Test salt generation */
    printf( "Testing salt generation:\n" );
    test_result = do_test_vector( SELFTEST_GENERATE_SALT, &print_results );
    print_test_result(test_result);
    if (!test_result) overall_result = EXIT_FAILURE;
    printf( "\n" );

    /* Test type 6 hash generation */
    printf( "Testing type 6 hash generation:\n" );
    test_result = do_test_vector( SELFTEST_GENERATE_TYPE_6, &print_results );
    print_test_result(test_result);
    if (!test_result) overall_result = EXIT_FAILURE;
    printf( "\n" );

    /* Test type 8 hash generation */
    printf( "Testing type 8 hash generation:\n" );
    test_result = do_test_vector( SELFTEST_GENERATE_TYPE_8, &print_results );
    print_test_result(test_result);
    if (!test_result) overall_result = EXIT_FAILURE;
    printf( "\n" );

    /* Test type 9 hash generation */
    printf( "Testing type 9 hash generation:\n" );
    test_result = do_test_vector( SELFTEST_GENERATE_TYPE_9, &print_results );
    print_test_result(test_result);
    if (!test_result) overall_result = EXIT_FAILURE;
    printf( "\n" );

    return overall_result;
}
