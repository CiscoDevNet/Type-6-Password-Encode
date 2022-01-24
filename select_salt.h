#if !defined(SELECT_SALT_H_)
#define SELECT_SALT_H_

#define AUTOGEN_SALT_LENGTH 14  /* We generate salts consisting of 14 */
                       /* characters (not including null termination) */

char *select_salt( char *buffer, int size_buffer );
void get_random_bytes(unsigned char *buffer, unsigned buffer_size);

#endif /* SELECT_SALT_H_ */
