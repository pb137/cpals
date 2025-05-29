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
    return bytes(enciphered)

def CBC_decoder(data, key, iv):

    last_block = iv 
    deciphered = bytearray() 
    for idx in range(0, len(data), AES_BLOCKSIZE):
        block = data[idx:idx+AES_BLOCKSIZE]
        decoded = AES128_decoder(block, key)
        xored = xor_buffers(decoded, last_block)
        deciphered += xored
        last_block = block    
 
    # print(f"Deciphered: {deciphered}")

    deciphered = unpad_pkcs7(deciphered, AES_BLOCKSIZE)

    return bytes(deciphered)

def random_aes_key():
    return secrets.token_bytes(AES_BLOCKSIZE)

class CBCPaddingOracle():
    def __init__(self):
        self._random_strings = [
            b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
            b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
            b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
            b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
            b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
            b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
            b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
            b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
            b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
            b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93',
        ]
        self._key = random_aes_key()
        # self._key = b'\x1c\xee\xb3\xde\xfdHG\x9e\x86\x84`\x03\xe1\xa4\xc0\x11'

    def encrypted(self):
        iv = random_aes_key()
        # iv = b'\xf7\xe0\xadtg\xcc-}\xfa\x1a\xb57V(\xac\x81'
        data = base64.b64decode(random.choice(self._random_strings))
        # data = base64.b64decode(self._random_strings[3])
        encoded = CBC_encoder(data, self._key, iv)
        return iv, encoded
    
    def padding_ok(self, data, iv):
        try:
            CBC_decoder(data, self._key, iv)
            return True
        except PaddingError:
            return False


def padding_oracle_decryptor(iv, encoded, padding_oracle):

    # List of candidate decodes
    decoded  = [[]]

    # Number of blocks in the message
    blocks = len(encoded) // AES_BLOCKSIZE

    # Iterate over all blocks except first
    for block_idx in range(blocks-1, 0, -1):
 
        # Candidate decode of blocks. There can be more than one valid decoding
        # of a block. We start with block initialised to zero
        block_candidates = [bytearray([0] * AES_BLOCKSIZE)]
        for idx in range(AES_BLOCKSIZE-1, -1, -1):

            test_block = bytearray(encoded[(block_idx-1)*AES_BLOCKSIZE:block_idx*AES_BLOCKSIZE])                
            ciphered_byte = test_block[idx]
            pad_block = bytes([0] * idx + [AES_BLOCKSIZE - idx] * (AES_BLOCKSIZE - idx)) 
            test_block = xor_buffers(pad_block, test_block)

            # List of block_candidates for next iteration. Only block_candidate entries 
            # that can be extended wil be propagated 
            updated_block_candidates = []
            
            # Attempt to extend decoding for each block
            for block_candidate in block_candidates:

                test_block_candidate = bytearray(xor_buffers(block_candidate, test_block))
                decoded_values = []

                for test_val in range(256):
                    test_block_candidate[idx] = test_val

                    # Copy encoded data and place test block candidate in position
                    data = bytearray(encoded[0:(block_idx-1)*AES_BLOCKSIZE])
                    data += test_block_candidate
                    data += bytearray(encoded[block_idx*AES_BLOCKSIZE:(block_idx+1)*AES_BLOCKSIZE])

                    if padding_oracle.padding_ok(data, iv):
                        # print(f"Padding for byte: {idx} test_val: {test_val} deciphred: {test_val^(AES_BLOCKSIZE - idx)}")
                        decoded_values.append( test_val^(AES_BLOCKSIZE - idx)^ciphered_byte )

                for val in decoded_values:
                    new_candidate = block_candidate[:]
                    new_candidate[idx] = val
                    updated_block_candidates.append(new_candidate)        

            block_candidates = updated_block_candidates

        updated_decoded = []
        for decode_candidate in decoded:
            for block_candidate in block_candidates:
                updated_decoded.append(block_candidate + bytes(decode_candidate))
        decoded = updated_decoded

    # Handle first block separately, where we mess with iv instead of the ciphertext
    block_candidate = bytearray([0] * AES_BLOCKSIZE)
    for idx in range(AES_BLOCKSIZE-1, -1, -1):

        test_block = bytearray(iv)            
        ciphered_byte = test_block[idx]
        pad_block = bytes([0] * idx + [AES_BLOCKSIZE - idx] * (AES_BLOCKSIZE - idx)) 
        test_block = xor_buffers(pad_block, test_block)
        test_block = bytearray(xor_buffers(block_candidate, test_block))

        for test_val in range(256):
            test_block[idx] = test_val

            # Copy encoded data and place test block in position
            data = bytearray(encoded[0:AES_BLOCKSIZE])

            if padding_oracle.padding_ok(data, test_block):
                # print(f"Padding for byte: {idx} test_val: {test_val} deciphred: {test_val^(AES_BLOCKSIZE - idx)}")
                block_candidate[idx] = test_val^(AES_BLOCKSIZE - idx)^ciphered_byte
                break

    updated_decoded = []
    for decode_candidate in decoded:
        updated_decoded.append(block_candidate + bytes(decode_candidate))
    decoded = updated_decoded    

    return decoded

def main():
    padding_oracle = CBCPaddingOracle()
    iv, encoded = padding_oracle.encrypted()
    decoded = padding_oracle_decryptor(iv, encoded, padding_oracle)

    print(f"Got decoded: {decoded}")

if __name__ == "__main__":
    sys.exit(main())