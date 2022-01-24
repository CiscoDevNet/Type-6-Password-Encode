__copyright__ = "Copyright (c) 2018 Cisco Systems. All rights reserved."

import hashlib
import secrets
from Crypto.Cipher import AES  # pycrypto==2.6.1
from Crypto.Hash import HMAC, SHA

# Not actually used but these are the 41 acceptable characters
# Which happen to be the 41 characters following ASCII 'A'
# b41_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghi"

TYPE6_SALT_LEN = 8
TYPE6_MAC_LEN = 4
TYPE6_PAD_LEN = 2


def base41_decode(three_symbols: str) -> bytes:
    assert len(three_symbols) == 3
    x = ord(three_symbols[0]) - ord("A")
    y = ord(three_symbols[1]) - ord("A")
    z = ord(three_symbols[2]) - ord("A")
    res = (x * 41 * 41) + (y * 41) + z
    return res.to_bytes(length=2, byteorder="big")


def base41_encode(two_bytes: bytes) -> str:
    assert len(two_bytes) == 2
    b41_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghi"
    number = int.from_bytes(bytes=two_bytes, byteorder="big")
    z = number % 41
    number //= 41
    y = number % 41
    number //= 41
    x = number
    return b41_chars[x] + b41_chars[y] + b41_chars[z]


def b41_decode(encoded_string: str) -> bytes:
    assert len(encoded_string) % 3 == 0
    decoded_bytes = b""
    for i in range(0, len(encoded_string), 3):
        chunk = encoded_string[i : i + 3]
        decoded_bytes += base41_decode(three_symbols=chunk)
    return decoded_bytes[: (-2 if decoded_bytes[-1] else -1)]


def b41_encode(binary: bytes) -> str:
    encoded_str = ""
    pad = (
        binary[-1].to_bytes(length=1, byteorder="big") + b"\x00"
        if len(binary) % 2
        else b"\x00\x01"
    )
    for i in range(0, len(binary), 2):
        val = binary[i : i + 2]
        if len(val) == 2:
            encoded_val = base41_encode(two_bytes=val)
            encoded_str += encoded_val
    encoded_str += base41_encode(two_bytes=pad)
    return encoded_str


def decrypt_type_6_password(encrypted_keystring: str, master_key: str) -> str:
    # The encrypted_keystring is base41(SALT + Encrypted Key + MAC)
    a = b41_decode(encrypted_keystring)
    salt = a[:TYPE6_SALT_LEN]
    encrypted_password = a[8 : (-1 * TYPE6_MAC_LEN)]

    # Generate the key used to generate the key that encrypted the password
    password = master_key.encode()
    password_md5_digest = hashlib.md5(password).digest()
    encryptor1 = AES.new(password_md5_digest, AES.MODE_ECB)

    # Verify the password MAC
    password_mac_verify(encrypted_keystring=encrypted_keystring, master_key=master_key)

    # This is the key that actually encrypted the key
    temp = salt + b"\x00" * 7 + b"\x01"
    ke = encryptor1.encrypt(plaintext=temp)
    encryptor1 = AES.new(ke, AES.MODE_ECB)

    temp_output = b""
    for x in range(len(encrypted_password)):
        if x % 16 == 0:
            # Key gets re-generated every block size
            temp = bytearray(16)
            temp[3] = x // 16
            temp = encryptor1.encrypt(plaintext=bytes(temp))
        c = encrypted_password[x] ^ (temp[x % 16])
        temp_output += c.to_bytes(length=1, byteorder="big")

    return temp_output.decode().rstrip("\x00")


def password_mac_verify(encrypted_keystring: str, master_key: str) -> None:
    a = b41_decode(encrypted_keystring)
    salt = a[:TYPE6_SALT_LEN]
    encrypted_password = a[TYPE6_SALT_LEN : (-1 * TYPE6_MAC_LEN)]
    mac = a[(-1 * TYPE6_MAC_LEN) :]

    password = master_key.encode()
    password_md5_digest = hashlib.md5(password).digest()
    encryptor1 = AES.new(password_md5_digest, AES.MODE_ECB)

    # This is the key that is used to authenticate the KEY
    temp = salt + b"\x00" * 8
    ka = encryptor1.encrypt(plaintext=temp)
    hmaccer = HMAC.new(ka, digestmod=SHA)
    hmaccer.update(encrypted_password)
    calculated_hash = hmaccer.digest()

    if calculated_hash[:TYPE6_MAC_LEN] != mac:
        raise ValueError("Password Validation failed")


def password_mac_generate(
    encrypted_key_bytes: bytes, master_key: str, salt: bytes
) -> bytes:
    password = master_key.encode()
    password_md5_digest = hashlib.md5(password).digest()
    encryptor1 = AES.new(password_md5_digest, AES.MODE_ECB)

    # This is the key that is used to authenticate the KEY
    temp = salt + b"\x00" * 8
    ka = encryptor1.encrypt(plaintext=temp)
    hmaccer = HMAC.new(ka, digestmod=SHA)
    hmaccer.update(encrypted_key_bytes)
    calculated_hash = hmaccer.digest()
    return calculated_hash[:TYPE6_MAC_LEN]


def encrypt_type_6_password(cleartext_password: str, master_key: str) -> str:
    # Generate the key used to generate the key that encrypted the password
    password = master_key.encode()
    password_md5_digest = hashlib.md5(password).digest()
    encryptor1 = AES.new(password_md5_digest, AES.MODE_ECB)
    salt = secrets.token_bytes(nbytes=TYPE6_SALT_LEN)
    cleartext = cleartext_password.encode()
    ke = encryptor1.encrypt(plaintext=salt + (b"\x00" * 7) + b"\x01")
    ke_encryptor = AES.new(ke, AES.MODE_ECB)

    temp_output = b""
    for x in range(len(cleartext)):
        if x % 16 == 0:
            # Key gets re-generated every block size
            temp = bytearray(16)
            temp[3] = x // 16
            temp = ke_encryptor.encrypt(plaintext=bytes(temp))
        c = ord(cleartext_password[x]) ^ (temp[x % 16])
        temp_output += c.to_bytes(length=1, byteorder="big")

    mac = password_mac_generate(
        encrypted_key_bytes=temp_output, master_key=master_key, salt=salt
    )

    return b41_encode(binary=salt + temp_output + mac)



###### Example usage ######

# This was a password (Cisco123) generated on a router with the master_key also set to Cisco123
enc_pass = "fe_a`iJYE\\DZYJhDhTP[`MYaTgRH_MAAB"
master_key = "Cisco123"
decrypted_pass = decrypt_type_6_password(
    master_key=master_key, encrypted_keystring=enc_pass
)
print(f"{enc_pass} is '{decrypted_pass}'")

# Test generating and decrypting
password_to_be_encrypted = "ABCD"
encrypted_password = encrypt_type_6_password(
    cleartext_password=password_to_be_encrypted, master_key=master_key
)
decrypted_generated_password = decrypt_type_6_password(
    encrypted_keystring=encrypted_password, master_key=master_key
)
print(
    f"'{password_to_be_encrypted}' encrypts to '{encrypted_password}'' decrypts to '{decrypted_generated_password}'"
)


