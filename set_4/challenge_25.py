import base64
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

def CTR_coder(data, key, nonce):
    nonce = nonce.to_bytes(8, 'little')
    blocks = len(data) // AES_BLOCKSIZE + 1
    keystream = b''
    for counter in range(blocks):
        counter_bytes = nonce + counter.to_bytes(8,'little') 
        keystream += AES128_encoder(counter_bytes, key)
    return xor_buffers(data, keystream)


class RandomAccessCTR:
    def __init__(self, key, nonce):
        self._key = key
        self._nonce = nonce

    def edit(self, ciphertext, offset, new_text):
        plaintext = CTR_coder(ciphertext, self._key, self._nonce )
        new_plaintext = plaintext[:offset] + new_text + plaintext[(len(new_text)+offset):]
        return CTR_coder(new_plaintext, self._key, self._nonce)

def main():

    # Data for this challenge is ECB encoded with key "YELLOW SUBMARINE"
    with open("set_4/challenge_25.txt","r") as f:
        text = f.read().replace('\n','')

    encoded = base64.b64decode(text)
    key = b"YELLOW SUBMARINE"
    plaintext = ECB_decoder(encoded,key)

    # Encrypt the data with AES CTR
    key = b"YELLOW SUBMARINE"
    nonce = 0
    ciphertext = CTR_coder(plaintext, key, nonce)

    ra_ctr = RandomAccessCTR(key, nonce)

    # Create a new plaintext the length of the original ciphertext
    blocksize = len(ciphertext)
    new_plaintext =  b'A' * blocksize

    # Get new ciphertext corresponding to all A's
    new_ciphertext = ra_ctr.edit(ciphertext, 0, new_plaintext)

    # Get keystream by xor'ing new_ciphertext with new_plaintext
    keystream = xor_buffers(new_plaintext, new_ciphertext)

    # Recover original keystream by xor'ing with the original ciphertext
    original_plaintext = xor_buffers(keystream, ciphertext)

    print(f"Original plaintext = {original_plaintext}") 

if __name__ == "__main__":
    sys.exit(main())
