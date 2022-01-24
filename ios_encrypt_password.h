#if !defined(IOS_ENCRYPT_PASSWORD_H_)
#define IOS_ENCRYPT_PASSWORD_H_

/*
 * This encrypts a password as an IOS type 6 password, and returns the full
 * hash.  The parameters:
 *
 * type - 6; it determines the type of password generated
 * master_key - the master key used for password encryption; this routine
 *        expects a null-terminated C string
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
char *ios_encrypt_password(int type, const char *master_key,
                    const char *password, const char *salt,
                    char *buffer, unsigned buffer_len);

#endif /* IOS_ENCRYPT_PASSWORD_H_ */
