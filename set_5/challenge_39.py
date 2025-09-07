import sys
import random
import hashlib
import secrets
import gensafeprime
import math

class RSAKey():
    def __init__(self, n, e, d):
        self.n = n
        self.e = e
        self.d = d

def two_primes(keylen_bits):
    """
    Create two 'safe' primes. If keylen_bits is too small (e.g. 8 bits or less)
    then we might not be able to find two safe primes
    """
    p = gensafeprime.generate(keylen_bits)

    attempts = 10
    count = 0
    while count < attempts:
        q = gensafeprime.generate(keylen_bits)
        if p != q:
            break
        count += 1

    if count == attempts:
        raise Exception('No safe primes found')

    return p, q

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        tmp = x - (b // a) * y
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def lcm(a, b):
    g, _, _ = egcd(a, b)
    return abs(a * b) // g

def rsa_keygen(keylen_bits):
    while True:
        p, q = two_primes(keylen_bits)
        n = p * q
        et = lcm(p-1, q-1)

        # Let's make a conventional choice of e = 65537 if we can
        if et > 65537:
            e = 65537
        else:
            e = 3

        # If e is prime, then we can test that e, et are not coprime
        # by testing the modulus != 0
        if (et % e) != 0:
            break
    
    d = modinv(e, et)

    return RSAKey(n, e, d)

def encode_message(payload, rsakey):
    payload_int = int.from_bytes(payload)
    if payload_int >= rsakey.n:
        raise Exception('Message too big. Quitting')

    return pow(payload_int, rsakey.e, rsakey.n)

def decode_message(payload, rsakey):
    
    decoded = pow(payload, rsakey.d, rsakey.n)

    n_bytes = 0x1
    while (0x1 << 8 * n_bytes) < decoded:
        n_bytes += 1 
    return decoded.to_bytes(n_bytes)

def main():

    rsakey = rsa_keygen(1024)

    msg = b"My super secret message"

    encoded = encode_message(msg, rsakey)
    decoded = decode_message(encoded, rsakey)

    print(f"encoded: {encoded}")
    print(f"decoded: {decoded}")

if __name__ == "__main__":
    sys.exit(main())