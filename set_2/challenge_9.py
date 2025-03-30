import sys
import base64
from cryptography.hazmat.primitives.padding import PKCS7

def pad_pkcs7(data, blocksize):
    if blocksize > 0:
        n = blocksize - len(data) % blocksize
        data += bytes([n] * n)
    return data

def main():

    data = b"YELLOW SUBMARINE"
    print(f"pad(data, 20): {pad_pkcs7(data,  20)}")
    print(f"pad(data, 16): {pad_pkcs7(data,  16)}")

    padder = PKCS7(128).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    print(f"padded_data: {padded_data}")

    data = b"YELLOW SUBMA"
    padder = PKCS7(128).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    print(f"padded_data: {padded_data}")


if __name__ == "__main__":
    sys.exit(main())