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

def random_aes_key():
    return secrets.token_bytes(AES_BLOCKSIZE)

def CTR_coder(data, key, nonce):
    nonce = nonce.to_bytes(8, 'little')
    blocks = len(data) // AES_BLOCKSIZE + 1
    keystream = b''
    for counter in range(blocks):
        counter_bytes = nonce + counter.to_bytes(8,'little') 
        keystream += AES128_encoder(counter_bytes, key)
    return xor_buffers(data, keystream)

class CTREnryptionOracle():
    def __init__(self):
        self._key = random_aes_key()
        self._nonce = random.randrange(0xffffffff)
        self._prefix = b'comment1=cooking%20MCs;userdata='
        self._postfix = b';comment2=%20like%20a%20pound%20of%20bacon'

    def encrypt(self, data):
        data = self._quote_input(data)
        data = self._prefix + data + self._postfix
        return CTR_coder(data, self._key, self._nonce)

    def decrypt(self, data):
        return CTR_coder(data, self._key, self._nonce)

    def is_admin(self, data):
        decoded = self.decrypt(data)
        print(f"is_admin: decode: {decoded}")
        return b';admin=true;' in decoded
    
    @staticmethod
    def _quote_input(data):
        data = data.replace(b";",b'\";\"')
        data = data.replace(b"=",b'\"=\"')
        return data

def main():

    ctr_oracle = CTREnryptionOracle()

    # Create a test string
    data = b'A'

    ciphertext = ctr_oracle.encrypt(data)

    # Our plaintext is the following
    plaintext = b'comment1=cooking%20MCs;userdata=A;comment2=%20like%20a%20pound%20of%20bacon'
    
    # Get keystream by xor'ing ciphertext with plaintext
    keystream = xor_buffers(plaintext, ciphertext)

    # Get new plaintext---------------------------------comment2=%20like%20a%20pound%20of%20bacon
    new_plaintext = b'comment1=cooking%20MCs;userdata=A;admin=true;comment2=%20like%20a%20pounder'

    # Create a new plaintext that will decode to the plaintext
    new_ciphertext = xor_buffers(new_plaintext, keystream)

    print(f"Have we won: {ctr_oracle.is_admin(new_ciphertext)}")

if __name__ == "__main__":
    sys.exit(main())