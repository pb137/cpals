import base64
import random
import secrets
import string
import sys
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

N = 624
M = 397
W = 32
R = 31
A = 0x9908b0df
B = 0x9d2c5680
C = 0xefc60000
F = 1812433253
U = 11
S = 7
T = 15
L = 18
UMASK = 0x80000000
LMASK = 0x7fffffff

class MersenneTwister:
    def __init__(self, seed=5489):
        self._state = [0] * N
        self._state[0] = int(seed) & 0xffffffff
        for i in range(1,N):
            self._state[i] = (F * (self._state[i-1] ^ (self._state[i-1] >> (W-2))) + i) & 0xffffffff
        self._ind = N

    @staticmethod
    def temper(y):
        y = y ^ (y >> U)
        y = y ^ ((y << S) & B)
        y = y ^ ((y << T) & C)
        y = (y ^ (y >> L)) 
        y = y & 0xffffffff
        return y

    @staticmethod
    def untemper(y):
        y = y ^ (y >> L)
        y = y ^ ((y << T) & C)
        z = (y ^ ((y << S) & B)) & (0xffffffff >> (R-S))
        z = (y ^ ((z << S) & B)) & (0xffffffff >> (R-2*S))
        z = (y ^ ((z << S) & B)) & (0xffffffff >> (R-3*S))
        z = (y ^ ((z << S) & B)) & (0xffffffff >> (R-4*S))
        y = (y ^ ((z << S) & B))
        z = y ^ ((y >> U) & (0xffffffff << (R-U)))
        z = y ^ ((z >> U) & (0xffffffff << (R-2*U)))
        y = y ^ (z >> U) 
        y = y & 0xffffffff
        return y

    def random(self):
        if self._ind >= N:
            self.twist()

        y = self._state[self._ind]
        self._ind += 1

        return self.temper(y)

    def twist(self):

        for k in range(N-M):
            y = (self._state[k]&UMASK)|(self._state[k+1]&LMASK)
            if y & 0x1:
                self._state[k] = self._state[k+M]^(y>>1)^A
            else:
                self._state[k] = self._state[k+M]^(y>>1)

        for k in range(N-M, N-1):
            y = (self._state[k]&UMASK)|(self._state[k+1]&LMASK)
            if y & 0x1:
                self._state[k] = self._state[k+(M-N)]^(y>>1)^A
            else:
                self._state[k] = self._state[k+(M-N)]^(y>>1)
            
        y = (self._state[N-1]&UMASK)|(self._state[0]&LMASK)
        if y & 0x1:
            self._state[N-1] = self._state[M-1]^(y>>1)^A
        else:
            self._state[N-1] = self._state[M-1]^(y>>1)

        self._ind = 0

def clone_mersenne_twister( original ):
    new_state = []
    for i in range(N):
        sample = original.random()
        untempered = MersenneTwister.untemper(sample)
        new_state.append(untempered)

    cloned = MersenneTwister(0)
    cloned._state = new_state

    return cloned



class MTStreamCipher:
    def __init__(self, key):
        self.mt = MersenneTwister(key)

    def key_stream(self):
        while True:
            r = self.mt.random()
            r = r.to_bytes(length=4, byteorder='big')
            yield r[0]
            yield r[1]
            yield r[2]
            yield r[3]

    def code(self, data):
        return bytes([a^b for a, b in zip(data, self.key_stream())])

def check_encoding():
    msg = b"This is my awesome message"
    
    mt_encoder = MTStreamCipher(0)
    encoded_msg = mt_encoder.code(msg)

    mt_decoder = MTStreamCipher(0)
    decoded_msg = mt_decoder.code(encoded_msg)

    print(f"Encoded: {encoded_msg}")
    print(f"Decoded: {decoded_msg}")

def recover_key(encoded):
    test_val = b'A' * 14 
    for key_cand in range(0xffff+1):
        mt_coder = MTStreamCipher(key_cand)
        decoded = mt_coder.code(encoded)

        if test_val in decoded:
            break;    

    return key_cand

def key_recovery():
    # Plaintext - random number of bytes plus 14 A's
    plaintext = secrets.token_bytes(random.randint(5,15)) + b'A' * 14

    key = random.randrange(0xffff)
    mt_coder = MTStreamCipher(key)
    encoded = mt_coder.code(plaintext)
    key_cand = recover_key(encoded)

    print(f"key:guess: {key}:{key_cand}")

def generate_random_password_reset_token(length):
    # Seconds since epoch as an int
    t = time.time_ns() // 1000000000
    key_stream = MTStreamCipher(t & 0xffffffff).key_stream()
    return bytes([a for (a,_) in zip(key_stream, range(length))])

def is_mt_reset_token(token, min_time, max_time):

    for seed in range(min_time, max_time+1):
        test_stream = MTStreamCipher(seed & 0xffffffff).key_stream()
        test_token = bytes([a for (a,_) in zip(test_stream, range(len(token)))])
        if test_token == token:
            return seed
    return 0

def main():
    reset_token = generate_random_password_reset_token(16)
    
    min_time = time.time_ns() // 1000000000 - 60
    max_time = min_time + 65 

    seed = is_mt_reset_token(reset_token, min_time, max_time)

    if seed > 0:
        print(f"Reset token: {reset_token} generated with seed: {seed}")
    else:
        print(f"Reset token: {reset_token} not generated with seed in range {min_time}-{max_time}")

if __name__ == "__main__":
    sys.exit(main())