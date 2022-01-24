#include "endian.h"

/*
 * This grabs 4 bytes from p, and interprets them as a bigendian
 * 32 bit value
 */
unsigned long get_ulong_bigendian(const unsigned char *p) {
    const unsigned char *q = p;
    int j;
    unsigned long temp = 0;

    for (j=0; j<4; j++) {
        temp = (temp<<8) + (*q++ & 0xff);
    }

    return temp;
}

/*
 * This grabs 4 bytes from p, and interprets them as a littleendian
 * 32 bit value
 */
unsigned long get_ulong_littleendian(const unsigned char *p) {
    const unsigned char *q = p;
    int j, shift;
    unsigned long temp = 0;

    for (j=0, shift=0; j<4; j++, shift+=8) {
        temp += (unsigned long)(*q++ & 0xff) << shift;
    }

    return temp;
}

/*
 * This shoves the 32 bit value into the next 4 bytes of p (in bigendian
 * format); that is, the most significant ("big") bits of value are placed
 * in the first byte.
 */
void put_ulong_bigendian( unsigned char *p, unsigned long value ) {
    int j, shift;

    for (j=0, shift=24; j<4; j++, shift-=8) {
        p[j] = (unsigned char)((value>>shift) & 0xff);
    }
}

/*
 * This shoves the 32 bit value into the next 4 bytes of p (in littleendian
 * format), that is, the least significant ("little") bits of value are
 * placed in the first byte
 */
void put_ulong_littleendian( unsigned char *p, unsigned long value ) {
    int j, shift;

    for (j=0, shift=0; j<4; j++, shift+=8) {
        p[j] = (unsigned char)((value>>shift) & 0xff);
    }
}
