import sys
import requests

def main():

    # All of shakespeare
    text = requests.get('http://ocw.mit.edu/ans7870/6/6.006/s08/lecturenotes/files/t8.shakespeare.txt').text
    text_bytes = text.encode('ascii')

    counts = [0] * 256
    for b in text_bytes:
        counts[b] += 1

    norm = sum(counts)
    counts = [ a / norm for a in counts]

    print("english_letter_frequencies=[")
    for i in counts:
        print(f"{i},", end="")
    print("]")


if __name__ == "__main__":
    sys.exit(main())