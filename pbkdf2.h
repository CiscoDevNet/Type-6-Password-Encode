#if !defined(PBKDF2_H_)
#define PBKDF2_H_

/*
 * This computes the PBKDF2 function based on the given password and salt
 * It uses SHA256 is its internal hash function
 *
 * Parameters:
 * - password, len_password - The password we're hashing
 * - salt, len_salt         - The salt we're includig in this password
 * - iterations             - The number of iterations to run
 * - output                 - Where to place the output of the hash (in binary;
 *                            if you need someone printable, you'll need to
 *                            asciiarmor it yourself)
 * - dkLen                  - Length of the desired hash
 */
int
pbkdf2_sha256(const char *password, unsigned password_len,
              const char *salt, unsigned salt_len,
              unsigned iterations,
              unsigned char *output, unsigned output_len);

#endif

