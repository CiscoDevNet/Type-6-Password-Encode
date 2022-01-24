#if !defined(ENDIAN_H_)
#define ENDIAN_H_

/*
 * These are a bunch of small routines that deal with endian issues; that is,
 * converting between strings of bytes, and bigendian/littleendian values
 */

/* Interpret 4 bytes as a bigendian 32 bit value */
unsigned long get_ulong_bigendian(const unsigned char *p);

/* Insert a bigendian 32 bit value into the 4 bytes */
void put_ulong_bigendian( unsigned char *p, unsigned long value );

/* Interpret 4 bytes as a littlendian 32 bit value */
unsigned long get_ulong_littleendian(const unsigned char *p);

/* Insert a littleendian 32 bit value into the 4 bytes */
void put_ulong_littleendian( unsigned char *p, unsigned long value );

#endif /* ENDIAN_H_ */
