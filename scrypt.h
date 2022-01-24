#if !defined( SCRYPT_H_ )
#define SCRYPT_H_

/*
 * This computes the scrypt function based on the given password and salt
 *
 * Parameters:
 * - password, len_password - The password we're hashing
 * - salt, len_salt         - The salt we're includig in this password
 * - r                      - The internal 'r' parameter we use internally
 *                            (which is the size of intermediate results).
 *                            Personally, I recommend r=1
 * - N                      - The number of logical elements we store
 *                            internally
 * - p                      - The parallelization factor.  Persoanlly, I
 *                            recommend p=1
 * - output                 - Where to place the output of the hash (in binary;
 *                            if you need someone printable, you'll need to
 *                            asciiarmor it yourself)
 * - dkLen                  - Length of the desired hash
 *
 * This returns 1 on success, 0 on failure
 */
int scrypt(const char *password, unsigned len_password,
           const char *salt, unsigned len_salt,
           unsigned r,
           unsigned N,
           unsigned p,
           unsigned char *output, unsigned dkLen);

#endif
