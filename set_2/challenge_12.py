import base64
import random
import secrets
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_BLOCKSIZE = 16

def pad_pkcs7(data, blocksize):
    if blocksize > 0:
        n = blocksize - len(data) % blocksize
        data += bytes([n] * n)
    return data

def unpad_pkcs7(data, blocksize):
    if blocksize > 0:
        n = data[-1]
        data = data[:-n]
    return data

def xor_buffers( bytes_a, bytes_b ):
    return bytes(a^b for a, b in zip(bytes_a, bytes_b))

def AES128_encoder(data, key):
    cipher = Cipher(algorithms.AES128(key), modes.ECB())
    cryptor = cipher.encryptor()
    coded_data = cryptor.update(data) + cryptor.finalize()
    return coded_data

def AES128_decoder(data, key):
    cipher = Cipher(algorithms.AES128(key), modes.ECB())
    cryptor = cipher.decryptor()
    coded_data = cryptor.update(data) + cryptor.finalize()
    return coded_data

def ECB_encoder(data, key):

    data = pad_pkcs7(data, AES_BLOCKSIZE)

    enciphered = bytearray() 
    for idx in range(0, len(data), AES_BLOCKSIZE):
        block = data[idx:idx+AES_BLOCKSIZE]
        encoded = AES128_encoder(block, key)
        enciphered += encoded
    return enciphered

def ECB_decoder(data, key):

    data = pad_pkcs7(data, AES_BLOCKSIZE)

    deciphered = bytearray() 
    for idx in range(0, len(data), AES_BLOCKSIZE):
        block = data[idx:idx+AES_BLOCKSIZE]
        decoded = AES128_decoder(block, key)
        deciphered += decoded

    deciphered = unpad_pkcs7(deciphered, AES_BLOCKSIZE)

    return deciphered

def CBC_encoder(data, key, iv):

    data = pad_pkcs7(data, AES_BLOCKSIZE)

    last_block = iv
    enciphered = bytearray() 
    for idx in range(0, len(data), AES_BLOCKSIZE):
        block = data[idx:idx+AES_BLOCKSIZE]
        xored = xor_buffers(block, last_block)
        encoded = AES128_encoder(xored, key)
        enciphered += encoded
        last_block = encoded
    return enciphered

def CBC_decoder(data, key, iv):

    last_block = iv 
    deciphered = bytearray() 
    for idx in range(0, len(data), AES_BLOCKSIZE):
        block = data[idx:idx+AES_BLOCKSIZE]
        decoded = AES128_decoder(block, key)
        xored = xor_buffers(decoded, last_block)
        deciphered += xored
        last_block = block    
 
    deciphered = unpad_pkcs7(deciphered, AES_BLOCKSIZE)

    return deciphered

def random_aes_key():
    return secrets.token_bytes(AES_BLOCKSIZE)

def encryption_oracle(data):

    key = random_aes_key()
    iv = random_aes_key()
    data = secrets.token_bytes(random.randint(5,10)) + data + secrets.token_bytes(random.randint(5,10))

    if random.randint(0,1) == 0:
        return CBC_encoder(data, key, iv)
    else:
        return ECB_encoder(data, key)

class EcbEncryptionOracle():

    def __init__(self):
        self._key = random_aes_key()
        self._unknown_string = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

    def encrypt(self, data):
        data += self._unknown_string
        return ECB_encoder(data, self._key)


def is_ecb_encoded(encryptor, blocksize):

    encoded = bytes(encryptor(bytes([0x41] * (10 * blocksize))))
    n_chunks = len(encoded) // blocksize
    chunks = set(encoded[idx:idx+blocksize] for idx in range(0, len(encoded), blocksize))
    if n_chunks > len(chunks):
        return True
    else:
        return False

def message_size(encryptor):
    encrypted = encryptor(b'')
    return len(encrypted)

def detect_block_size(encryptor):
    initial_sz = len(encryptor(bytes([0x41] * 0)))
    for sz in range(1,50):
        encrypted = encryptor(bytes([0x41] * sz))
        if len(encrypted) > initial_sz:
            return len(encrypted) - initial_sz

def byte_at_a_time_decoder():

    oracle = EcbEncryptionOracle()

    blocksize = detect_block_size(oracle.encrypt)
    print(f"Blocksize: {blocksize}")
    is_ecb = is_ecb_encoded(oracle.encrypt, blocksize)
    print(f"ECB encoded: {is_ecb}")
    msg_size = message_size(oracle.encrypt)
    print(f"Message size: {msg_size}")

    decoded = []
    while len(decoded) < msg_size:

        # This is the index we're working on
        block = len(decoded) // blocksize
        for sz in range(1,blocksize+1):

            # Construct a vector of known bytes
            prefix = bytes( [0x41] * (blocksize - sz))
            prefix += bytes(decoded)

            # Construct a lookup table for the unknown byte
            lookup_table = {}
            for i in range(256):
                plaintext = prefix + bytes([i])
                encoded = oracle.encrypt(plaintext)
                encoded = encoded[(block * blocksize):((block + 1) * blocksize)]
                lookup_table[bytes(encoded)] = i 

            # Find the real value
            prefix = bytes( [0x41] * (blocksize - sz))
            encoded = oracle.encrypt(prefix)
            encoded = encoded[(block * blocksize):((block + 1) * blocksize)]

            if bytes(encoded) in lookup_table:
                decoded += bytes([lookup_table[bytes(encoded)]])
                decoded_str = bytes(decoded).decode("ascii")
                print(f"Decoded: {decoded_str}")
            else:
                print(f"Decodeding failed - we must be done")
                return decoded

def main():
    decoded = byte_at_a_time_decoder()
    decoded_str = bytes(decoded).decode("ascii")
    print(f"Decoded: {decoded_str}")


if __name__ == "__main__":
    sys.exit(main())

