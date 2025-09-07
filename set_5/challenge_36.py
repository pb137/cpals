import sys
import hashlib
import hmac
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

def key_pair(g, n):

    len_n = n.bit_length() // 8

    # Choose a random value for private key
    a = int.from_bytes(secrets.token_bytes(len_n))

    # Calculate public key
    A = pow(g, a, n)

    return a, A

class SRPCommon:

    salt_size_bytes = 4

    def __init__(self, n, g, k, email, passwd ):
        # All of these values will eventually be common to both sides
        self.n = n
        self.len_n = n.bit_length() // 8
        self.g = g
        self.k = k
        self.email = email
        self.passwd = passwd
        self.salt = None
        self.u = None
        self.K = None
        self.A = None
        self.B = None

    def set_u(self):
        if self.A is not None and self.B is not None:
            uH = hashlib.sha256()
            uH.update(f"{self.A}{self.B}".encode("utf-8"))
            self.u = int.from_bytes(uH.digest())
            return
        raise Exception("Calculating u before both A and B known")

    def _x(self):
        if self.salt is not None:
            xH = hashlib.sha256()
            xH.update(f"{self.salt}{self.passwd}".encode("utf-8"))
            return int.from_bytes(xH.digest())
        raise Exception("Calculating x before salt known")

    def set_K(self):
        pass

    def hmac(self, key, msg):
        if self.K is not None and self.salt is not None:
            h = hmac.new( self.K, self.salt, hashlib.sha256)
            return h.hexdigest()
        raise Exception("Calculating state before A known")


class SRPServer(SRPCommon):

    def __init__(self, n, g, k, email, passwd):
        super().__init__(n, g, k, email, passwd)
        self.salt = int.from_bytes(secrets.token_bytes(SRPServer.salt_size_bytes))
        self.v = pow(self.g, self._x(), self.n)
        self.b, self.B = key_pair(self.g, self.n)
        self.B = (self.B + self.k * self.v) % self.n

    def s_to_c_msg_1(self):
        return self.salt, self.B

    def set_K(self):
        if self.A is not None:
            S = (self.A * pow(self.v, self.u, self.n))
            S = pow(S, self.b, self.n)
            KH = hashlib.sha256()
            KH.update(S.to_bytes(self.len_n))
            self.K = KH.digest()
            return
        raise Exception("Calculating state before A known")


class SRPClient(SRPCommon):

    def __init__(self, n, g, k, email, passwd):
        super().__init__(n, g, k, email, passwd)
        self.a, self.A = key_pair(self.g, self.n)

    def c_to_s_msg_1(self):
        return self.email, self.A

    def set_K(self):
        if self.salt is not None:
            x = self._x()   
            S = (self.B - self.k * pow(self.g, x, self.n))
            S = pow(S, self.a + self.u * x, self.n)
            KH = hashlib.sha256()
            KH.update(S.to_bytes(self.len_n))
            self.K = KH.digest()
            return
        raise Exception("Calculating state before salt known")

def main():

    # Initialise client and server with information known to both
    server = SRPServer(p, 2, 3, "client@email.com", "SuperSecretPassword")
    client = SRPClient(p, 2, 3, "client@email.com", "SuperSecretPassword")

    # Client sends email and public key. Server stores public key
    email, server.A = client.c_to_s_msg_1()

    # Server sends salt and its public key. Client stores salt and public key
    client.salt, client.B = server.s_to_c_msg_1()

    # Client and server can now calculate u
    client.set_u()
    server.set_u()

    # Assert both identical
    assert client.u == server.u, "u values don't match"
    
    # Client and server can now calculate K
    client.set_K()
    server.set_K()

    # Assert both identical
    assert client.K == server.K, "K values don't match"

if __name__ == "__main__":
    sys.exit(main())
