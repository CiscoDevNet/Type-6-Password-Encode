AR = /usr/bin/ar
CC = /usr/bin/gcc
CFLAGS = -Wall -g
%.o : %.cpp ; $(CPP) -c $(CFLAGS) $< -o $@

all: epp epp.a

#
# This is the standalone executable to convert passwords; it can be
# invoked as a child process by the application
epp: epp.a epp.c
	$(CC) $(CFLAGS) -o epp epp.c epp.a

#
# This is the library that is designed to be directly integrated into
# the application
epp.a: ios_hash_password.o ios_encrypt_password.o convert_bitstring.o \
	hmac_sha1.o hmac_sha256.o scrypt.o endian.o select_salt.o \
 	pbkdf2.o sha1.o sha256.o md5.o aes.o test_vector.o
	$(AR) rcs $@ $^

clean:
	-rm *.o *.a epp


