import base64
import random
import secrets
import sys
import hashlib

def f_k(t, b, c, d):
    if 0 <= t <= 19:
        f = (b & c) | ((~b) & d)
        k = 0x5A827999
    elif 20 <= t <= 39:
        f = b ^ c ^ d
        k = 0x6ED9EBA1
    elif 40 <= t <= 59:
        f = (b & c) | (b & d) | (c & d)
        k = 0x8F1BBCDC
    elif 60 <= t <= 79:
        f = b ^ c ^ d
        k = 0xCA62C1D6 
    return f, k

def rotl(x, n):
    # Rotate x left n in 32 bits
    return ((x << n) & 0xffffffff) | (x >> (32-n))

def padding(msg):
    
    blocksize = 64

    # Message length in bits
    message_len = 8 * len(msg)

    # Pad message to multiple of 512 bits, after adding extra byte + 8 byte message length
    to_pad = (len(msg) + 9) % blocksize
    if to_pad > 0:
        to_pad = blocksize - to_pad

    # Pad message with one bit (80), rest of zeros and then message length as big endian 64 
    padding = b'\x80' + to_pad * b'\x00' + message_len.to_bytes(8, byteorder='big') 

    return padding

def sha1sum(msg):

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # Number of bytes in message = 64 bytes * 8 = 512 bits
    blocksize = 64

    # Pad message with one bit (80), rest of zeros and then message length as big endian 64 
    padded_msg = msg + padding(msg) 

    if len(padded_msg) % 64 != 0:
        print(f"Error - padded data must be multiple of 64: {len(padded_msg)}")
        return

    blocks = len(padded_msg) // blocksize
    for block in range(blocks):

        w = [int.from_bytes(bytes(padded_msg[(block * blocksize + i * 4):(block * blocksize + (i + 1) * 4)]), 'big', signed=False) for i in range(16)]
        w = w + [0] * (80-16) 

        for t in range(16,80):
            v = w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]
            w[t] = rotl(v, 1)

        a = h0
        b = h1
        c = h2
        d = h3 
        e = h4

        for t in range(80):
            f, k = f_k(t, b, c, d)

            tmp = ( rotl(a, 5) + f + e + k + w[t]) & 0xffffffff
            e = d
            d = c
            c = rotl(b, 30)
            b = a
            a = tmp
        
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    return h0.to_bytes(4,byteorder='big') + h1.to_bytes(4,byteorder='big') + h2.to_bytes(4,byteorder='big') + h3.to_bytes(4,byteorder='big') + h4.to_bytes(4,byteorder='big')     

def create_mac(key, message):
    return sha1sum(key + message)

def check_mac(key, message, mac):
    return sha1sum(key + message) == mac

def check_sha1_implementation():

    for i in range(256):

        print(f"Check: {i}")
        # Generate random message
        msg = random.randbytes(random.randrange(10, 2500)) 

        hasher = hashlib.sha1()
        hasher.update(msg)
        lib_digest = hasher.hexdigest()

        my_digest = sha1sum(msg).hex()

        if my_digest != lib_digest:
            print(f"Error: {lib_digest} != {my_digest}")
        else:
            print("Ok")

def main():

    check_sha1_implementation()

    key = b"YELLOW SUBMARINE"
    message = b"The quick brown fox jumped over the lazy cog"
    mac = create_mac(key, message)

    print(f"Original message: {message}")
    print(f"Check mac: {check_mac(key, message, mac)}")

    message_array = bytearray(message)
    message_array[10] = 106
    message = bytes(message_array)

    print(f"Updated message: {message}")
    print(f"Check mac: {check_mac(key, message, mac)}")

if __name__ == "__main__":
    sys.exit(main())