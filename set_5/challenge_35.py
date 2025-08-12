import sys
import random
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

p_hex = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" \
        "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" \
        "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" \
        "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" \
        "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" \
        "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" \
        "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" \
        "fffffffffffff"
p = int(p_hex, 16)
len_p = p.bit_length() // 8

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

def key_pair(g):

    # Choose a random value for private key
    a = int.from_bytes(secrets.token_bytes(len_p))

    # Calculate public key
    A = pow(g, a, p)

    return a, A

def shared_secret(priv, pub):
    return pow(pub, priv, p)

def shared_secret_to_AES_key(shared):

    hasher = hashlib.sha1()
    hasher.update(shared.to_bytes(length=len_p))
    return hasher.digest()[0:16]

def encode_message(payload, key):
    iv = random_aes_key()
    return iv + CBC_encoder(payload, key, iv)

def decode_message(payload, key):
    iv = payload[0:16]
    return CBC_decoder(payload[16:], key, iv)

def machine_in_the_middle():

    # A and B agree (p, g)
    # MITM modifies g on the way and sets it to (1, p or p-1)
    # Both A and B end up using same values of (p, g) 

    for g in [1, p, p-1]:
        
        a, A = key_pair(g)
        b, B = key_pair(g)

        # shared secret at a
        shared_a = shared_secret(a, B)

        # shared secret at b
        shared_b = shared_secret(b, A)

        print(f"g={g}") 
        # If a * b is even, then, when g = p-1, shared secret will be 1   as (p-1)%p == -1%p and (-1)^(ab) == (-1)^2 = 1
        # If a * b is odd,  then, when g = p-1, shared secret will be p-1 as (p-1)%p == -1%p and (-1)^(ab) == (-1)^1 = -1 = p-1
        print(f"a * b % 2 = {(a * b) %2}")
        print(f"shared_a={shared_a}")
        print(f"shared_b={shared_b}")
        print("-------------------")

def main():
    machine_in_the_middle()


if __name__ == "__main__":
    sys.exit(main())
