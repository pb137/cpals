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

    def random(self):
        if self._ind >= N:
            self.twist()

        y = self._state[self._ind]
        self._ind += 1

        y = y ^ (y >> U)
        y = y ^ ((y << S) & B)
        y = y ^ ((y << T) & C)
        y = (y ^ (y >> L)) 
        y = y & 0xffffffff
        return y

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

class TimeSeeder:
    def __init__(self):
        self._seed = random.randrange(40,1000) + int(time.time())
        self._generator = MersenneTwister(self._seed)
        self._future_timestamp = self._seed + random.randrange(40, 1000)

    def random(self):
        return self._generator.random()
    
    def time(self):
        return self._future_timestamp

    def seed(self):
        return self._seed

def find_seeds(t_0, t_end, rand):

    seeds = []
    for seed in range(t_0, t_end):
        mt = MersenneTwister(seed)
        if mt.random() == rand:
            seeds.append(seed)

        if seed % 50 == 0:
            print(f"Checking seed: {seed}")
        
    return seeds

def main():

    t_0 = int(time.time())

    time_seeder = TimeSeeder()

    rand = time_seeder.random()

    t_end = time_seeder.time()

    print(f"t_0: {t_0} t_end: {t_end} diff: {t_end - t_0}")

    seeds = find_seeds(t_0, t_end, rand)

    print(f"Seed candidates: {seeds}")
    print(f"Real seed: {time_seeder.seed()}")

if __name__ == "__main__":
    sys.exit(main())