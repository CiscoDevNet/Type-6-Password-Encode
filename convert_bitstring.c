/*
 * This function converts a bitstring into a printable ASCII string
 */
#include "convert_bitstring.h"

/* The translation between 6 bit groups and printable characters */
static char printable_char_arr[64] =
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* This converts a 6 bit value into a printable character */
char convert_6_bit_into_char(int n) {
    return printable_char_arr[ n & 0x3f ];
}

/* 
 * get_printable_hash() converts the non-printable input string to 
 * printable output string. The output characters will belong to the 
 * set defined in printable_char_arr[]. The algo is to map every 6 bit
 * group of input stream to a character in printable_char_arr[].
 *
 * For example, if len is 32, input stream will contain 32*8=256 bits.
 * This has to be made as a multiple of 6 by appending '0' bits. i.e. 
 * 256+2=258=43*6. The output length will be 43 character.
 *
 * The mapping is as follows: we take three successive characters with the bits
 *  A7 A6 A5 A4 A3 A2 A1 A0
 *  B7 B6 B5 B4 B3 B2 B1 B0
 *  C7 C6 C5 C4 C3 C2 C1 C0
 * we remap them into four six-bit segment:
 *  A7 A6 A5 A4 A3 A2
 *  A1 A0 B7 B6 B5 B4
 *  B3 B2 B1 B0 C7 C6
 *  C5 C4 C3 C2 C1 C0
 * We then map each six-bit segment as an index in printable_char_arr and
 * output that character
 *
 * We take the entire string in 3 byte chunks; if the string isn't a multiple
 * of 3 in length, there will be a final partial block consisting of 1 or 2
 * bytes.
 * We map this partial ending block as; if we have one character at the end
 *  A7 A6 A5 A4 A3 A2 A1 A0
 * we remap it as 
 *  A7 A6 A5 A4 A3 A2
 *  A1 A0  0  0  0  0
 * and if we have two characters at the end
 *  A7 A6 A5 A4 A3 A2 A1 A0
 *  B7 B6 B5 B4 B3 B2 B1 B0
 * we remap it as 
 *  A7 A6 A5 A4 A3 A2
 *  A1 A0 B7 B6 B5 B4
 *  B3 B2 B1 B0  0  0
 *
 * This function will work properly for any value of len. If the provided
 * buffer isn't long enough, this will error out
 */
int get_printable_hash(const unsigned char *inp, unsigned int len, char *out, unsigned out_buffer_len) {
    unsigned int i,k,n;
    unsigned long j;
    unsigned out_index = 0;  /* Where in the output buffer we are */

    if (!inp || !out || !len || out_buffer_len < 1) {
        return 0;
    }

    for ( ; len; len -= n, inp += n) {
        int partial_output;
        /* Take a group of 3 input characters at a time
         * and convert them into output characters 
         * Of course, if there are fewer than 3 left, take what's there
         */
        n = (len > 3) ? 3 : len;

        /* combine the chars into a single word, in bigendian order */
        j = 0;
        for (i = 0; i<n; i++) {
            j = (j<<8) | (inp[i] & 0xff);
        }

        /*
         * The bits are now in the order 
         * A7 A6 A5 A4 A3 A2 A1 A0 B7 B6 B5 B4 B3 B2 B1 B0 C7 C6 C5 C4 C3 C2 C1 C0
         */

        /*
         * If we don't take up an even number of output characters (which is
         * 6 bits each), this is the number of bits we have in the partial
         * output
         */
        partial_output = (n * 8 % 6);

        /*
         * If there is a partial output, that is, we're outputing only 1 or
         * 2 bytes as a part of the final chunk, move the bits up so that the
         * partial output is at the front (the most significant side) of the 6
         * bit boundary; we'll be doing the output in bigendian order
         */
        if (partial_output > 0) j <<= (6 - partial_output);

        /*
         * If we're doing a partial block, the bits are now in the order:
         * A7 A6 A5 A4 A3 A2 A1 A0  0  0  0  0
         * A7 A6 A5 A4 A3 A2 A1 A0 B7 B6 B5 B4 B3 B2 B1 B0  0  0
         */

        /*
         * Calculate the number of output chars for this iteration; this is
         * the number of 6 bit chunks we have, including the partial (hence
         * we round up)
         */
        k = (n * 8 + 5) / 6;

        /*
         * Output each successive 6 bit chunks as an encoded character,
         * starting at the top (that is, in bigendian order)
         */
        for (i = 0; i < k; i++) {
            int bit_position, this_output;
            char output_char;

            bit_position = 6 * (k - i - 1); /* The bits we're outputing this */
                        /* iteration are bit_position+5 through bit_position */
            this_output = (j>>bit_position) & 0x3f; /* The 6 bit chunk to */
                        /* output */
            output_char = convert_6_bit_into_char(this_output); /* The 6 bit */
                        /* chunk encoded as a printable string */

            /* Add the encoded character to the output string */
            if (out_index == out_buffer_len) return 0; /* Oops, ran into */
                                          /* the end of the supplied buffer */
            out[out_index] = output_char;
            out_index++;
        }
    }

    /* The output is expected to be a null-terminated string */
    if (out_index == out_buffer_len) return 0; /* Oops, ran into */
                                 /* the end of the supplied buffer */
    out[out_index] = '\0';

    return 1; /* Success */
}

/* Compute how long an encode byte string of a given length would encode into */
unsigned get_printable_hash_output_len(unsigned input_len) {
    unsigned num_full_outputs = input_len/3;
    unsigned num_bytes_in_last_partial = input_len%3;
    const unsigned size_last_partial_output[3] = {
        0,   /* 0 byte partial blocks don't take up any space */
        2,   /* 1 byte partial blocks are encoded as 2 characters */
        3,   /* 2 byte partial blocks are encoded as 3 characters */
    };

    /* Return the length of the encoding, which is:
     *   4 characters for each 3-byte full chunk
     *   The space used for the last partial chunk
     * : 1 for the null terminator
     */
    return 4*num_full_outputs
           + size_last_partial_output[ num_bytes_in_last_partial ]
           + 1;
}

static const char base41_characters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghi";

static void base41encode(char *encoded, unsigned short value) {
    int x,y,z;

    /* 41^3 = 68921 > 65536 */
    z = value % 41; value /= 41;
    y = value % 41; value /= 41;
    x = value;

    encoded[0] = base41_characters[x];
    encoded[1] = base41_characters[y];
    encoded[2] = base41_characters[z];
}

static int reverse_lookup(char digit, const char *base, int size_base) {
    int i;
    for (i=0; i<size_base; i++) {
        if (*base++ == digit) {
            return i;
        }
    }
    return -1;
}

static long base41decode(const char *encoded) {
    int x,y,z;
    long digit;

    x = reverse_lookup(encoded[0], base41_characters, 41);
    y = reverse_lookup(encoded[1], base41_characters, 41);
    z = reverse_lookup(encoded[2], base41_characters, 41);

    if (x<0 || y<0 || z<0) return -1;

    digit = 41*41L*x + 41L*y + z;

    if (digit > 65535) return -1;

    return digit;
}

/* 
 * get_printable_hash_type_6() converts the non-printable input string to 
 * printable output string, in the alternate method used by type 6. The output
 * characters will belong to the set defined in printable_char_arr_type_6[].
 * The algorithm is to convert adjacent 16 bits into base 41, and print out
 * that triple of digits (encoding each digit in printable_char_arr_type_6).
 *
 * For example, if len is 32, input stream will consist of 32/2=16 words.
 * Each word will be expressed as 3 charactesr, giving us an output length
 * of 48 characters, plus 3 at the end as the 'end-of-message' marker.
 *
 * This function will work properly for any value of len. If the provided
 * buffer isn't long enough, this will error out
 */
int get_printable_hash_type_6(const unsigned char *inp, unsigned int len, char *out, unsigned out_buffer_len) {
    unsigned short digit;

    if (!inp || !out || !len || out_buffer_len < 1) {
        return 0;
    }

    while (len > 1) {
        digit = 256 * inp[0] + inp[1];

        if (out_buffer_len < 3) return 0;

        base41encode( out, digit );

        out += 3;
        out_buffer_len -= 3;
        inp += 2;
        len -= 2;
    }

    if (len == 1) {
        /* Odd number of bytes; add the last byte, along with a 0 byte */
        digit = 256 * inp[0] ;
    } else {
        /* Even number of bytes; add the 'nothing more' marker at the end */
        digit = 1;
    }

    if (out_buffer_len < 4) return 0;

    base41encode( out, digit );

    out[3] = '\0';

    return 1; /* Success */
}

/*
 * This converts an ASCII-armored string back into binary
 * This returns 1 on success
 */
int decode_printable_hash_type_6(const char *encode, unsigned len_encode,
                                 unsigned char *orig_text, unsigned orig_text_len) {
    while (len_encode >= 3) {
        long digit = base41decode(encode);
        if (digit < 0) return 0;  /* Illegal digit */
        encode += 3;
        len_encode -= 3;

        if (orig_text_len < 2) return 0; /* Buffer overflow */

        *orig_text++ = 0xff & (digit >> 8);
        *orig_text++ = 0xff & (digit     );
        orig_text_len -= 2;
    }

    return 1;
}

unsigned get_printable_hash_output_type_6_len(unsigned input_len) {
    if (input_len % 2) {
        input_len += 1;   /* Odd length strings add a single terminator byte */
    } else {
        input_len += 2;   /* Even length strings add two terminator bytes */
    }

    /* Return the length of the encoding, which is:
     *   3 characters for each 2-byte chunk
     * + 1 for the null terminator
     */
    return 3*(input_len/2) + 1;
}




