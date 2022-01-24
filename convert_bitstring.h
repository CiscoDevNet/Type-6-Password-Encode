#if !defined( CONVERT_BITSTRING_H_ )
#define CONVERT_BITSTRING_H_

/* Convert an entire bypestring into a human readable string */
int get_printable_hash(const unsigned char *inp, unsigned int len, char *out, unsigned out_buffer_len);

/* Convert an entire bypestring into a human readable string, using the method that type 6 uses */
int get_printable_hash_type_6(const unsigned char *inp, unsigned int len, char *out, unsigned out_buffer_len);

/* Convert a string encoded via the type 6 method back into binary */
int decode_printable_hash_type_6(const char *encode, unsigned len_encode,
                                 unsigned char *orig_text, unsigned orig_text_len);

/* Compute how long an encode byte string of a given length would encode into */
unsigned get_printable_hash_output_len(unsigned input_len);

/* Compute how long an encode byte string of a given length would encode into */
unsigned get_printable_hash_output_type_6_len(unsigned input_len);


/* Convert a single 6-bit segment into a human readable character */
char convert_6_bit_into_char(int n);

#endif /* CONVERT_BITSTRING_H_ */
