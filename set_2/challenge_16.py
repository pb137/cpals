import base64
import random
import secrets
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_BLOCKSIZE = 16

class PaddingError(Exception):
    pass

def pad_pkcs7(data, blocksize):
    if blocksize > 0:
        n = blocksize - len(data) % blocksize
        data += bytes([n] * n)
    return data

def unpad_pkcs7(data, blocksize):
    if blocksize > 0:        
        n = data[-1]
        if data[-n:] != bytes([n] *n):
            raise PaddingError("help")
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


class CBCEnryptionOracle():
    def __init__(self):
        self._key = random_aes_key()
        self._iv = random_aes_key()
        self._prefix = b'comment1=cooking%20MCs;userdata='
        self._postfix = b';comment2=%20like%20a%20pound%20of%20bacon'

    def encrypt(self, data):
        data = self._quote_input(data)
        data = self._prefix + data + self._postfix
        data = pad_pkcs7(data, AES_BLOCKSIZE)
        return CBC_encoder(data, self._key, self._iv)

    def decrypt(self, data):
        return CBC_decoder(data, self._key, self._iv)

    def is_admin(self, data):
        decoded = self.decrypt(data)
        return b';admin=true;' in decoded
    
    @staticmethod
    def _quote_input(data):
        data = data.replace(b";",b'\";\"')
        data = data.replace(b"=",b'\"=\"')
        return data

def main():

    cbc_oracle = CBCEnryptionOracle()

    data = b"this_is_some;data=thing;admin=true;that needs padding"
    escaped = cbc_oracle._quote_input(data)
    print(f"Escaped: {escaped}")

    # Blocks 0, 1 - 32 characters
    # [comment1=cooking%20MCs;userdata=]
    # [ABCDabcdABCDabcdABCDabcdABCDabcd] = 32 characters
    
    # Set userdata to two blocks of known text
    userdata = b'A' * 32

    # Message we want to send will terminate userdata and add padding
    message = b';admin=true;' + b'\x04\x04\x04\x04'

    # Round trip userdata to generate ciphertext    
    encoded = cbc_oracle.encrypt(userdata)
    decoded = cbc_oracle.decrypt(encoded)

    print(f"Original decode: {decoded}")

    # Take block 2 which is ciphertext of first set of AAAA's
    c_2 = encoded[(2 * AES_BLOCKSIZE):((2 + 1) * AES_BLOCKSIZE)]

    # New ciphertext, which will corrupt block 2 is equal to 'AAAA' ^ c_2 ^ message
    tmp = xor_buffers(b'A' * 16, c_2)
    c_2_new = xor_buffers(tmp, message)

    # Reconstruct new ciphertext, taking first two blocks of original
    new_encoded = encoded[(0 * AES_BLOCKSIZE):((1 + 1) * AES_BLOCKSIZE)]

    # Plus our new modified block
    new_encoded += c_2_new

    # Plus our original block 3
    new_encoded += encoded[(3 * AES_BLOCKSIZE):((3 + 1) * AES_BLOCKSIZE)]

    # Decoded it and check it ends ';admin=true;'
    decoded = cbc_oracle.decrypt(bytes(new_encoded))
    print(f"Decoded: {decoded}")

    print(f"Have we won: {cbc_oracle.is_admin(new_encoded)}")

if __name__ == "__main__":
    sys.exit(main())