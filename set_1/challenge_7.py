import base64
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def main():

    with open("set_1/challenge_7.txt","r") as f:
        text = f.read().replace('\n','')

    encoded_bytes = base64.b64decode(text)

    key = b"YELLOW SUBMARINE"
    cipher = Cipher(algorithms.AES128(key), modes.ECB())
    decryptor = cipher.decryptor()
    decoded_bytes = decryptor.update(encoded_bytes) + decryptor.finalize()

    decoded_str = decoded_bytes.decode("ascii")
    
    print(f"Decoded text:\n {decoded_str}")

if __name__ == "__main__":
    sys.exit(main())