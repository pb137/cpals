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
 
    try:
        deciphered.decode('ascii')
    except UnicodeDecodeError:
        raise EncodingError("Decoded text not ascii", deciphered)     

    deciphered = unpad_pkcs7(deciphered, AES_BLOCKSIZE)

    return deciphered

def random_aes_key():
    return secrets.token_bytes(AES_BLOCKSIZE)

class EncodingError(Exception):
    pass


class CBCEnryptionOracle():
    def __init__(self, key):
        self._key = key
        self._iv = self._key
        self._prefix = b'comment1=cooking%20MCs;userdata='
        self._postfix = b';comment2=%20like%20a%20pound%20of%20bacon'

    def encrypt(self, data):
        data = self._quote_input(data)
        data = self._prefix + data + self._postfix
        data = pad_pkcs7(data, AES_BLOCKSIZE)
        return CBC_encoder(data, self._key, self._iv)

    def decrypt(self, data):

        plaintext = CBC_decoder(data, self._key, self._iv)
        return plaintext

    def is_admin(self, data):
        decoded = self.decrypt(data)
        return b';admin=true;' in decoded
    
    @staticmethod
    def _quote_input(data):
        data = data.replace(b";",b'\";\"')
        data = data.replace(b"=",b'\"=\"')
        return data

def main():

    cbc_oracle = CBCEnryptionOracle(b"YELLOW SUBMARINE")

    plaintext = b"This is some arbitrary encoded data that will be at least three blocks (48 characters) long"

    # Round trip userdata to generate ciphertext    
    ciphertext = cbc_oracle.encrypt(plaintext)

    if len(ciphertext) > 3 * AES_BLOCKSIZE:
        print(f"Length of ciphertext: {len(ciphertext)}")

        C_0 = ciphertext[0:AES_BLOCKSIZE]

        new_ciphertext = C_0 + b'\0' * AES_BLOCKSIZE + C_0

        # Try to decrypte the new ciphertext

        try:
            plaintext = cbc_oracle.decrypt(new_ciphertext)
        except EncodingError as e:  
            msg, decoded = e.args
            print(f"Error: {msg}")
            P_1 = decoded[:AES_BLOCKSIZE]
            P_2 = decoded[2*AES_BLOCKSIZE:3*AES_BLOCKSIZE]
            key = xor_buffers(P_1,P_2)
            print(f"Got key as: {key}")

if __name__ == "__main__":
    sys.exit(main())