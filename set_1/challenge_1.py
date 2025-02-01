import sys
import base64

def main():

    hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    base64_str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

    hex_as_bytes = bytes.fromhex(hex_str)
    hex_as_base64_str = base64.b64encode(hex_as_bytes).decode('utf-8')
    assert( hex_as_base64_str == base64_str )
    print(f"{hex_as_base64_str} {base64_str}") 

if __name__ == "__main__":
    sys.exit(main())