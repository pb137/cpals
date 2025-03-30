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

def is_ecb_encoded(encryptor):

    input = bytes([0x41] * (10 * AES_BLOCKSIZE))

    output = bytes(encryptor(input))

    n_chunks = len(output) // AES_BLOCKSIZE

    # Split msg into chunks and store into set
    chunks = set(output[idx:idx+AES_BLOCKSIZE] for idx in range(0, len(output), AES_BLOCKSIZE))

    if n_chunks > len(chunks):
        return True
    else:
        return False

def main():

    for i in range(10):
        print(f"Test: {i} {is_ecb_encoded(encryption_oracle)}")


if __name__ == "__main__":
    sys.exit(main())