#if !defined(IOS_HASH_PASSWORD_H_)
#define IOS_HASH_PASSWORD_H_

/*
 * This hashes a password as an IOS type 8 or type 9 password, and
 * returns the full hash.  The parameters:
 *
 * type - either 8 or 9; it determines the type of password generated
 * password - the original password string; this routine expects a
 *        null-terminated C string
 * salt - the salt to use while hashing the password.  If NULL, then the
 *        routine will select a salt value.  If salt is provided, this
 *        routine expects a null-terminated C string
 * buffer - if not NULL, the routine will place the password into the buffer.
 *        If NULL, the routine will malloc the space to store the buffer,
 *        and return that
 * buffer_len - the length of the above buffer (if provided)
 *
 * This will return either a pointer to the hash (formatted as a
 * null-terminated C string), or NULL on error
 *
 * If buffer == NULL, this routine expects the caller to free the memory
 */
char *ios_hash_password(int type, const char *password, const char *salt,
                    char *buffer, unsigned buffer_len);

/*
 * This computes how long an IOS password would be, given the hash type and
 * the salt.  If the salt is not given (salt==NULL), then this assumes that
 * we'll use an autogenerated salt
 *
 * This includes the null-termination at the end of the password
 *
 * Note that the length does not depend on the actual password; hence that
 * is not passed
 */
unsigned ios_hash_passwordlen(int type, const char *salt);

#endif /* IOS_HASH_PASSWORD_H_ */
