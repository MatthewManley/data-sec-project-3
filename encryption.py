import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# AES-CBC-256 uses 32 byte keys
key_bytes = 32


# Encrypts a string using a key provided in hex. 
# Returns the IV and ciphertext in hex.
def encryptAesCbc(cleartext: str, key_hex: str):
    key_bytes = hex_to_bytes(key_hex)
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    encrypted_bytes = cipher.encrypt(pad(cleartext, AES.block_size))
    encrypted_hex = bytes_to_hex(encrypted_bytes)
    iv_hex = bytes_to_hex(cipher.iv)
    return (iv_hex, encrypted_hex)

# Dencrypts a string using a key and IV provided in hex. 
# Returns the cleartext.
def decryptAesCbc(encrypted_hex: str, key_hex: str, iv_hex: str) -> str:
    encrypted_bytes = hex_to_bytes(encrypted_hex)
    key_bytes = hex_to_bytes(key_hex)
    iv_bytes = hex_to_bytes(iv_hex)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    return unpad(cipher.decrypt(encrypted_bytes, AES.block_size))

# Encrypts a string using SHA256
# Returns the digest as 
def encryptSha256(cleartext: str) -> str:
    cleartext_bytes = cleartext.encode('utf-8')
    sha = hashlib.sha256()
    sha.update(cleartext_bytes)
    digest_bytes = sha.digest()
    return bytes_to_hex(digest_bytes)

# Generates length number of bytes and returns it as a hex string
def generate_key(length: int):
    random_bytes = get_random_bytes(32)
    return bytes_to_hex(random_bytes)

# Converts bytes to a hex string
def bytes_to_hex(data: bytes, byte_order = 'big') -> str:
    integer = int.from_bytes(data, byte_order)
    return hex(integer)[2:] # Chop off the 0x at the start of the string

# Converts a hex string to bytes
def hex_to_bytes(data: str, byte_order = 'big') -> bytes:
    return bytearray.fromhex(data)

class InvertedIndex:
    data = {}

    def addEntry(key, value):
        pass

    
