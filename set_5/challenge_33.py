import sys
import random
import secrets

p_hex = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" \
        "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" \
        "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" \
        "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" \
        "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" \
        "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" \
        "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" \
        "fffffffffffff"
p = int(p_hex, 16)
g = 2


def key_pair():

    # Choose a random value for secret key
    mod_len = p.bit_length() // 8
    a = int.from_bytes(secrets.token_bytes(mod_len))

    # Calculate public key
    A = pow(g, a, p)

    return a, A

def simple():

    p = 37
    g = 5

    # Private key for A
    a = random.randrange(0,sys.maxsize * 2 + 1) % p
    
    # Public key for A
    A = (g ** a) % p

    # Private key for B
    b = random.randrange(0,sys.maxsize * 2 + 1) % p
    
    # Public key for B
    B = (g ** b) % p

    # Session key for A
    s_a = (B**a) % p

    # Session key for B
    s_b = (A**b) % p

    assert s_a == s_b, "Keys do not match"


def bigger():
    a, A = key_pair()
    b, B = key_pair()

    s_a = pow(B, a, p)
    s_b = pow(A, b, p)

    assert s_a == s_b, "Keys do not match"


def main():
    simple()
    bigger()


if __name__ == "__main__":
    sys.exit(main())
