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
g = 2

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

def key_pair():

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

def message_exchange():

    # Key pairs
    a, A = key_pair()
    b, B = key_pair()

    # Shared secret and keys for A
    shared_a = shared_secret(a, B)
    key_a = shared_secret_to_AES_key(shared_a)

    # Message A --> B 
    encoded_a = encode_message(b"This is my awesome message", key_a)

    # Shared secret and keys for B
    shared_b = shared_secret(b, A)
    key_b = shared_secret_to_AES_key(shared_b)

    decoded_b = decode_message(encoded_a, key_b)

    print(f"B: Received: {decoded_b} from A")

def machine_in_the_middle():

    # Key pairs
    a, A = key_pair()
    b, B = key_pair()

    # shared secret at a uses p instead of B
    shared_a = shared_secret(a, p)
    key_a = shared_secret_to_AES_key(shared_a)

    # shared secret at b uses p instead of A
    shared_b = shared_secret(b, p)
    key_b = shared_secret_to_AES_key(shared_b)

    # Message A --> B 
    encoded_a = encode_message(b"This is my awesome message", key_a)
    decoded_b = decode_message(encoded_a, key_b)

    print(f"MITM: shared_a: {shared_a}")
    print(f"MITM: shared_b: {shared_b}")

    # Shared secret at M is zero (equal to shared_a and shared_b) hence M can decrypt messages
    key_m = shared_secret_to_AES_key(0)
    decoded_m = decode_message(encoded_a, key_m)

    print(f"MITM M: Received: {decoded_m} from A")
    print(f"MITM B: Received: {decoded_b} from A")


def main():
    message_exchange()
    machine_in_the_middle()


if __name__ == "__main__":
    sys.exit(main())
