import base64
import random
import secrets
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_BLOCKSIZE = 16

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

def CTR_coder(data, key, nonce):
    nonce = nonce.to_bytes(8, 'little')
    blocks = len(data) // AES_BLOCKSIZE + 1
    keystream = b''
    for counter in range(blocks):
        counter_bytes = nonce + counter.to_bytes(8,'little') 
        keystream += AES128_encoder(counter_bytes, key)
    return xor_buffers(data, keystream)

def random_aes_key():
    return secrets.token_bytes(AES_BLOCKSIZE)

def main():

    encoded_b64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="    
    encoded = base64.b64decode(encoded_b64)
    key = b"YELLOW SUBMARINE"
    nonce = 0
    decoded = CTR_coder(encoded, key, nonce)

    plaintext = b"THis is my superlong message that I'd like to encode"
    key = b"YELLOW SUBMARINE"
    nonce = 0

    encoded = CTR_coder(plaintext, key, nonce)
    decoded = CTR_coder(encoded, key, nonce)

    print(f"decoded: {decoded}")


if __name__ == "__main__":
    sys.exit(main())