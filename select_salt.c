#include <stdio.h>
#include <time.h>
#include <string.h>
#include "select_salt.h"
#include "convert_bitstring.h"
#include "sha256.h"

#define STATE_FILE "eppsave"  /* Where we store our hoard of entropy */

/*
 * This will select a salt with at least 80 bits of entropy to use within a
 * password
 * Actually, we do 84 bits; 14 characters times 6 bits per character
 */
char *select_salt( char *buffer, int size_buffer )
{
    unsigned char salt[ AUTOGEN_SALT_LENGTH ];
    int i;

    if (size_buffer <= AUTOGEN_SALT_LENGTH) return 0; /* <= because we need */
                                           /* space for the null terminator */

    /* Pick our random bits */
    get_random_bytes(salt, AUTOGEN_SALT_LENGTH);

    /* Convert the lower 6 bits of each byte into a printable character */
    /* This gives us our 14 character random string */
    for (i=0; i<AUTOGEN_SALT_LENGTH; i++) {
        buffer[i] = convert_6_bit_into_char( salt[i] & 0x3f );
    }
    buffer[i] = '\0';

    return buffer;
}

/*
 * This tries to get a bunch of random-looking bytes.
 *
 * Now, we're trying to live within the bounds of C89.  However, that doesn't
 * give us a great wealth of places to get entropy from.  Here's what we do try
 * to use:
 * - The time() function.  Of course, the implementation doesn't have to
 *   actually give us a real value; however, it might (and I believe that most
 *   computers will)
 * - Reading a value from a file.  Again, the implementation doesn't have to
 *   allow us to have access to files; again, it might (and I believe that most
 *   computers will)
 *
 * We attempt to read those sources, and hash what we have together, and output
 * some of the bytes of the hash as our 'random bytes'.
 * Then, we hash again, and then save that hash back into the file (hopefully
 * for next time).
 *
 * So, the file we save is a complex function of both the previous file
 * contents and the time we read; that means that if both are working (that is,
 * we have a working time() function, and we can actualy save/restore entropy
 * between runs), then we'll build up entropy over multiple uses.
 *
 * This procedure is no where close to cryptographically secure; we wouldn't
 * even think of it if we were generating keys.  However, the security
 * properties that we need for salts are uniqueness (two different hashes
 * should not use the same salt) and exact unpredictability (an attacker
 * should not be able to predict the exact value beforehand); this procedure
 * comes close to that.
 *
 * If the customer has a better source of entropy, they are perfectly free to
 * replace these rather weak sources with a better one.
 */
#define NUM_STORED_VALUES SHA256_LEN
void get_random_bytes(unsigned char *buffer, unsigned buffer_size) {
    time_t value1;
    int value2[NUM_STORED_VALUES] = { 0 };
    FILE *f;
    SHA256_CTX ctx;
    unsigned char hash[SHA256_LEN];

    /* Set value1 to the current time */
    value1 = time(0);

    /* Read value2 from our state file */
    f = fopen( STATE_FILE, "r" );
    if (f) {
        int i;
        for (i=0; i<NUM_STORED_VALUES; i++) {
            (void)fscanf( f, "%d\n", &value2[i] );
        }
        fclose(f);
    }

    /* Hash value1 and value2 together to come up with the new 'state' */
    SHA256Init( &ctx );   
    SHA256Update( &ctx, &value1, sizeof value1 );
    SHA256Update( &ctx, value2, sizeof value2 );
    SHA256Final(hash, &ctx );

    /* Use the first buffer_size bytes of the hash as the output */
    if (buffer_size > SHA256_LEN) buffer_size = SHA256_LEN;
    memcpy( buffer, hash, buffer_size );

    /*
     * Rehash the value (so the value we save is independent of the salt we
     * just came up with)
     */
    SHA256Init( &ctx );   
    SHA256Update( &ctx, hash, sizeof hash );
    /* We have the original entropy just sitting around; might as well toss those in */
    SHA256Update( &ctx, &value1, sizeof value1 );
    SHA256Update( &ctx, value2, sizeof value2 );
    SHA256Final(hash, &ctx );

    /* Save that updated hash into the state file */
    f = fopen( STATE_FILE, "w" );
    if (f) {
        int i;
        for (i=0; i<NUM_STORED_VALUES; i++) {
            fprintf( f, "%d\n", hash[i] );
        }
        fclose(f);
    }
}
