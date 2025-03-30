import sys

def main():

    msgs = []
    with open("set_1/challenge_8.txt") as f:
        for line in f:
            msgs.append(line.rstrip())

    chunksize = 16
    for (id, msg) in enumerate(msgs):

        # Number of chunks we should get - AES 128 blocks are 128 / 8 = 16 bytes long
        n_chunks = len(msg) // chunksize

        # Check msg length is a multiple of chunksize
        if len(msg) % chunksize != 0:
            print(f"msg:{id} length ({len(msg)}) not a multiple of {chunksize}") 

        # Split msg into chunks and store into set
        chunks = set(msg[idx:idx+chunksize] for idx in range(0, len(msg), chunksize))

        # If msg contains identical chunks, set will have fewer than n_chunks entries
        if len(chunks) != n_chunks:
            print(f"msg:{id} contains identical chunks. Total: {len(chunks)} Should be: {n_chunks}")

if __name__ == "__main__":
    sys.exit(main())