import sys

def f_k(t, b, c, d):
    if 0 <= t <= 19:
        f = (b & c) | ((~b) & d)
        k = 0x5A827999
    elif 20 <= t <= 39:
        f = b ^ c ^ d
        k = 0x6ED9EBA1
    elif 40 <= t <= 59:
        f = (b & c) | (b & d) | (c & d)
        k = 0x8F1BBCDC
    elif 60 <= t <= 79:
        f = b ^ c ^ d
        k = 0xCA62C1D6 
    return f, k

def rotl(x, n):
    # Rotate x left n in 32 bits
    return ((x << n) & 0xffffffff) | (x >> (32-n))

def padding(msg):
    
    blocksize = 64

    # Message length in bits
    message_len = 8 * len(msg)

    # Pad message to multiple of 512 bits, after adding extra byte + 8 byte message length
    to_pad = (len(msg) + 9) % blocksize
    if to_pad > 0:
        to_pad = blocksize - to_pad

    # Pad message with one bit (80), rest of zeros and then message length as big endian 64 
    padding = b'\x80' + to_pad * b'\x00' + message_len.to_bytes(8, byteorder='big') 

    return padding

def sha1sum(msg):

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    padding_bytes = padding(msg) 

    return _sha1sum(msg, padding_bytes, h0, h1, h2, h3, h4)

def _sha1sum(msg, padding_bytes, h0, h1, h2, h3, h4):

    # Number of bytes in message = 64 bytes * 8 = 512 bits
    blocksize = 64

    # Pad message with one bit (80), rest of zeros and then message length as big endian 64 
    padded_msg = msg + padding_bytes

    if len(padded_msg) % 64 != 0:
        print(f"Error - padded data must be multiple of 64: {len(padded_msg)}")
        return

    blocks = len(padded_msg) // blocksize
    for block in range(blocks):

        w = [int.from_bytes(bytes(padded_msg[(block * blocksize + i * 4):(block * blocksize + (i + 1) * 4)]), 'big', signed=False) for i in range(16)]
        w = w + [0] * (80-16) 

        for t in range(16,80):
            v = w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]
            w[t] = rotl(v, 1)

        a = h0
        b = h1
        c = h2
        d = h3 
        e = h4

        for t in range(80):
            f, k = f_k(t, b, c, d)

            tmp = ( rotl(a, 5) + f + e + k + w[t]) & 0xffffffff
            e = d
            d = c
            c = rotl(b, 30)
            b = a
            a = tmp
        
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    return h0.to_bytes(4,byteorder='big') + h1.to_bytes(4,byteorder='big') + h2.to_bytes(4,byteorder='big') + h3.to_bytes(4,byteorder='big') + h4.to_bytes(4,byteorder='big')     

def create_mac(key, message):
    return sha1sum(key + message)

def check_mac(key, message, mac):
    return sha1sum(key + message) == mac

def extend_mac( mac, original_message, message_addition, key_length ):

    # Returns new_message and new_mac by extending mac of the original_message with message_addition,
    # assuming key_length is correct

    # Message we will construct will be:
    # original_message || glue_padding || message_addition

    # This should pass a mac check with the new mack

    # Break mac down into constants
    h0 = int.from_bytes(bytes(mac[0:4]), 'big', signed=False)
    h1 = int.from_bytes(bytes(mac[4:8]), 'big', signed=False)
    h2 = int.from_bytes(bytes(mac[8:12]), 'big', signed=False)
    h3 = int.from_bytes(bytes(mac[12:16]), 'big', signed=False)
    h4 = int.from_bytes(bytes(mac[16:20]), 'big', signed=False)
    
    # Calculate padding of original message based on key length by constructing a dummy message of right length
    glue_padding = padding(b'\x00' * (len(original_message)+key_length))

    # Create new mac. Padding must be length of total message: len(key || original_message || glue_padding || message_addition)
    new_message_padding = padding(b'\x00' * (key_length + len(original_message) + len(glue_padding) + len(message_addition)))
    new_mac = _sha1sum(message_addition, new_message_padding, h0, h1, h2, h3, h4)

    # Create new message
    new_message = original_message + glue_padding + message_addition

    return new_message, new_mac 


def main():

    key = b"YELLOW SUBMARINE"
    original_message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

    mac = create_mac(key, original_message)
    print(f"Original message: {original_message}")
    print(f"Check mac: {check_mac(key, original_message, mac)}")

    message_addition = b";admin=true"

    key_length = len(key)

    new_message, new_mac = extend_mac( mac, original_message, message_addition, key_length )
    print(f"New message: {new_message}")
    print(f"Check mac: {check_mac(key, new_message, new_mac)}")

if __name__ == "__main__":
    sys.exit(main())