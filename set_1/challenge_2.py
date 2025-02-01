import sys
import base64

def xor_buffers( bytes_a, bytes_b ):
    return bytes(a^b for a, b in zip(bytes_a, bytes_b))

def main():
    bytes_a = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    bytes_b = bytes.fromhex("686974207468652062756c6c277320657965")
    bytes_c = bytes.fromhex("746865206b696420646f6e277420706c6179")    
    xored = xor_buffers(bytes_a, bytes_b)
    assert(xored == bytes_c)    
    print(f"{xored}")


if __name__ == "__main__":
    sys.exit(main())