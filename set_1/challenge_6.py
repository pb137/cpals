import math
import sys
import base64

def xor_buffers( bytes_a, bytes_b ):
    return bytes(a^b for a, b in zip(bytes_a, bytes_b))

def xor_buffer_with_byte( bytes_buf, xor_val ):
    return bytes(a^xor_val for a in  bytes_buf)

def xor_buffer_with_repeated_key( bytes_buf, key ):
    key_buf = key * int( math.ceil(len(bytes_buf) / len(key)) )
    return bytes(a^b for a, b in zip(bytes_buf, key_buf))

def hamming_distance( bytes_a, bytes_b ):
    return sum((a^b).bit_count() for a, b in zip(bytes_a, bytes_b))

def score_english( byte_str ):

    english_letter_weights=[0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.022801660401168957,0.0,0.0,
                            0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,
                            0.0,0.0,0.23706244495666062,0.0016203146862179265,8.610898943039636e-05,
                            1.8321061580935398e-07,0.0,1.8321061580935398e-07,3.8474229319964335e-06,
                            0.005692170622580818,0.00011505626672827429,0.00011523947734408364,1.15422687959893e-05,
                            0.0,0.015238359759327207,0.0014792425120447239,0.014295008298524843,9.160530790467698e-07,
                            5.477997412699684e-05,0.00017001945147108048,6.705508538622355e-05,6.045950321708681e-05,
                            1.703858727026992e-05,1.5023270496367025e-05,1.15422687959893e-05,7.511635248183512e-06,
                            7.328424632374159e-06,0.00017368366378726755,0.0003347257950836897,0.0031510393813050787,
                            8.574256819877765e-05,1.8321061580935398e-07,8.07958815719251e-05,0.0019193144112187922,
                            1.4656849264748318e-06,0.008150307454894921,0.0028238252214695726,0.0039384786080536825,
                            0.0028732920877380984,0.00780165765300972,0.002145945942974963,0.0020453633148956275,
                            0.0033824343890722927,0.010224251625856808,0.00037869634287793463,0.0011351729755547572,
                            0.0043710388719795665,0.002907918894126066,0.005008611814996119,0.006084241340412836,
                            0.002187351542147877,0.00021582210542341897,0.005307611539996984,0.006231176254291938,
                            0.007291782509212288,0.0025885827907703622,0.0006558940045974872,0.003022242318391103,
                            0.00011102563318046851,0.0016670333932493116,9.746804761057631e-05,0.000381994133962503,
                            0.0,0.0003805284490360282,0.0,1.3007953722464131e-05,1.8321061580935398e-07,0.044825042106379775,
                            0.008527171691614762,0.012217949547094197,0.024509732972359564,0.0741308625793966,0.01260543999953098,
                            0.010449417472686504,0.04001429775645776,0.036309412683561006,0.0004968671900749679,0.005351948509022848,
                            0.026778246817310985,0.017511270659058054,0.03955956900801894,0.051553818393209924,0.008523873900530193,
                            0.0004404383204056869,0.03827159837887919,0.039386251765463294,0.053126498319317414,0.021035876485998403,
                            0.006227145620744132,0.013354954628807049,0.0008588913669142513,0.015622552420679421,0.00020134846677448,
                            0.0,6.045950321708681e-06,3.6642123161870795e-07,1.8321061580935398e-07,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,
                            0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,
                            0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,
                            0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,
                            0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,
                            0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0]

    observed = [0] * 256
    val = 1.0 / len(byte_str)
    for ind in byte_str:
        observed[ind] += val

    return sum(a*b for a, b in zip(observed, english_letter_weights))

class DecodeResult:
    def __init__(self, xor, score, decoded):
        self.xor = xor
        self.score = score
        self.decoded = decoded

def decode_xor_byte(encoded):
    max_score = 0.0
    max_xor = -1
    max_decoded = []
    for xor in range(256):
        decoded = xor_buffer_with_byte(encoded, xor)
        score = score_english(decoded)
        if score > max_score:
            max_score = score
            max_xor = xor
            max_decoded = decoded

    return DecodeResult(max_xor, max_score, max_decoded)

def find_xor_keysize( encoded, max_size ):

    print(f"Finding key size, max: {max_size}")

    score = [sys.float_info.max]
    for keysize in range(1, max_size+1):

        # split encoded text into blocks of length keysize
        chunks = [encoded[idx:idx+keysize] for idx in range(0, len(encoded), keysize)]

        # Find edit distance by calculating / sampling hamming distance for blocks
        count = 0;
        sum = 0.0;
        for i in range(len(chunks)):
            for j in range(i+1,len(chunks)):
                sum += hamming_distance( chunks[i], chunks[j]) / keysize
                count += 1
                if count > 1000:
                    break

        score.append(sum / count)
        print(f"keysize: {keysize} chunks: {len(chunks)} score:  {sum / count}")

    keysize = min(range(len(score)), key=score.__getitem__)

    print(f"Found key size: {keysize}")

    return keysize, score

def decode_xor_for_keysize( encoded, keysize ):

    print(f"Decoding for key size: {keysize}")

    key = bytearray()
    decoded = bytearray(len(encoded))
    for i in range(keysize):

        # Pull out i'th set of encoded bytes
        chunk = [encoded[j] for j in range(i, len(encoded), keysize)]
        
        # Decode it, assuming it has english one letter stats
        result = decode_xor_byte(chunk)

        # Store key byte, in case it's interesting
        key.append(result.xor)

        # Write it back to decoded array
        for j in range(len(result.decoded)):
            decoded[i+j*keysize] = result.decoded[j]

    return key, decoded

def decode_xor_key(encoded, max_keysize):

    keysize, _ = find_xor_keysize(encoded, max_keysize)
    key, decoded = decode_xor_for_keysize(encoded, keysize)

    return key, decoded

def main():

    hamming_test = hamming_distance(b"this is a test", b"wokka wokka!!!")
    print(f"hamming distance: {hamming_test}")

    with open("set_1/challenge_6.txt","r") as f:
        text = f.read().replace('\n','')

    encoded_bytes = base64.b64decode(text)

    key, decoded = decode_xor_key(encoded_bytes, 40)
    
    decoded_str = decoded.decode("ascii")
    key_str = key.decode("ascii")

    print(f"Decoded:\n {decoded_str}")
    print(f"Key: {key_str}")

if __name__ == "__main__":
    sys.exit(main())