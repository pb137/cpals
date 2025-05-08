import sys

AES_BLOCKSIZE = 16

class PaddingError(Exception):
    pass

def pad_pkcs7(data, blocksize):
    if blocksize > 0:
        n = blocksize - len(data) % blocksize
        data += bytes([n] * n)
    return data

def unpad_pkcs7(data, blocksize):
    if blocksize > 0:        
        n = data[-1]
        if data[-n:] != bytes([n] *n):
            raise PaddingError("help")
        data = data[:-n]
    return data


def main():
    data = b'AAAAAAAAAA\x06\x06\x06\x06\x06\x06'
    data = unpad_pkcs7(data, AES_BLOCKSIZE)
    print(f"Unpadded: {data}")

    data = b'AAAAAAAAAA\x06\x06\x06\x06\x06\x05'

    try: 
        data = unpad_pkcs7(data, AES_BLOCKSIZE)
        print(f"Unpadded: {data}")
    except PaddingError as e:
        print(f"Caught error: {e}")
    

if __name__ == "__main__":
    sys.exit(main())