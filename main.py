import argparse as ap
import base64
from itertools import cycle
from functools import reduce
import doctest
import pyaes

freq = b'etaoinshrdlcumwfgypbvkjxqz'
engl = b' ,.\'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ:\n'


def repeats(a: bytes) -> bool:
    """
    >>> repeats(b'ii')
    True
    >>> repeats(b'iii')
    False
    """
    if len(a) % 2 == 1:
        return False

    h = int(len(a)/2)

    return a[:h] == a[h:]


def eng_score(a: bytes) -> int:
    """
    >>> eng_score(b'hel\x0flo!')
    5
    """
    return len(list(filter(lambda c: c in engl, a)))

def ham(a: bytes, b: bytes) -> int:
    """
    Hamming Distance

    >>> ham('this is a test'.encode(), 'wokka wokka!!!'.encode())
    37
    """
    assert len(a) == len(b)
    dist = 0
    for x, y in zip(a, b):
        d = x^y
        while d > 0:
            if d&1:
                dist += 1
            d >>= 1
    return dist


def divide(a: bytes, size: str) -> list:
    """
    >>> list(divide('abcde', 2))
    ['ab', 'cd', 'e']
    >>> list(divide('abcde', 100))
    ['abcde']
    """
    for start in range(0, len(a), size):
        yield a[start:start + size]


def transpose(data: bytes, keylen) -> list:
    """
    >>> list(transpose(b'abc', 2))
    [b'ac', b'b']
    >>> list(transpose(b'abcde', 2))
    [b'ace', b'bd']
    >>> list(transpose(b'abcde', 3))
    [b'ad', b'be', b'c']
    """
    blocks = list(divide(data, keylen))

    for index in range(keylen):
        t = []
        for b in filter(lambda block: len(block) > index, blocks):
            t.append(b[index])
        yield bytes(t)



def solve_block_keys(data: bytes):
    """
    1) Determine shortest likely keysizes.
    2) Create transpose blocks for each likely keysize.
    3) Find the best single char xor key for each transpose block.
    4) combine all single char xor keys for a key for each keysize.
    5) gen typles of (keylen, key_for_keylen)
    """
    for keylen, hamdist in keysize_by_hamdist(data):
        key_parts = []
        for trans in transpose(data, keylen):
            key, score, decoded = xor_key_w_most_engl(trans)
            key_parts.append(key)
        if not repeats(key_parts):
            yield (keylen, hamdist, bytes(key_parts))


def keysize_by_hamdist(data: bytes) -> tuple:
    """
    Given a blob, finds keysizes with the minimum
    hamming distance where hamming distance is:
        ham(data[0:keylen], data[keylen:2*keylen]) / keylen

        * actually average over 4 keys
    """
    assert len(data) >= 4
    finds = []
    for keylen in range(2, 40):
        a, b, c, d, *_ = divide(data, keylen)
        avg_ham = (ham(a, b) + ham(c, d)) / (2.0 * keylen)
        finds.append( (keylen, avg_ham) )

    return tsort(finds, 1)[:7]


def xor_cycle(data: bytes, key: bytes) -> bytes:
    return bytes([x^y for x, y in zip(data, cycle(key))])


def xor_key_w_most_engl(a: bytes) -> tuple:
    """
    Xor the string against all single character strings.
    Return the decoded string with the most english characters.
    """
    max_score = 0
    winner = None
    for key in range(256):
        decoded = xor_cycle(a, bytes([key]))
        score = eng_score(decoded)
        if score >= max_score:
            max_score = score
            if score == len(decoded):
                decoded = decoded.decode()
            winner = (key, score, decoded)

    return winner


def tsort(l: list, index: int, reverse=False) -> list:
    """
    Sorts a list of tuples by an column in that tuple.

    Largest at index 0
    """
    return sorted(l, key=lambda w: w[index], reverse=reverse)


def file_lines(fname: str, decode=16) -> list:
    with open(fname) as f:
        lines = [line.strip() for line in f.readlines()]
        if decode is None:
            return [line.encode() for line in lines]
        if decode == 16:
            return [from_hex_str(line) for line in lines]
        if decode == 64:
            return from_b64(''.join(lines))


def file_blob(fname: str, decode=None) -> list:
    with open(fname) as f:
        data = f.read()
        if decode is None:
            return data.encode()
        if decode == 16:
            return from_hex_str(data)
        if decode == 64:
            return from_b64(data)

def from_hex_str(a: str) -> bytes:
    return bytes.fromhex(a)

def from_b64(a: str) -> bytes:
    return base64.b64decode(a)

def to_b16(a: bytes) -> str:
    return base64.b16encode(a)

def to_b64(a: bytes) -> str:
    return base64.b64encode(a)

def plist(l: list):
    for r in l:
        print(r)


def aes_ecb_decode(blob: bytes, key: bytes) -> bytes:
    """
    Decodes the blob in 16 bytes chunks.
    Returns the concatination of all 16 byte results.
    """
    aes = pyaes.AESModeOfOperationECB(key)
    comb = bytearray()
    for b in divide(blob, 16):
        comb += aes.decrypt(b)
    return comb


def main():
    parser = ap.ArgumentParser()
    parser.add_argument('--a', type=str)
    parser.add_argument('--b', type=str)
    parser.add_argument('--dout', type=str)
    args = parser.parse_args()

    a = args.a
    b = args.b

    if args.dout == 'ch1':
        print(to_b64(from_hex_str(a)))

    if args.dout == 'ch2':
        print(to_b16(xor_cycle(from_hex_str(a), from_hex_str(b))))

    if args.dout == 'ch3':
        data = from_hex_str(a)
        print(xor_key_w_most_engl(data))

    if args.dout == 'ch4':
        data = file_lines(a, decode=16)
        print(tsort(map(xor_key_w_most_engl, data), 1, reverse=True)[0])

    if args.dout == 'ch5':
        data = file_blob(a, decode=None)
        print(data)
        key = b.encode()
        print(to_b16(xor_cycle(data, key)))

    if args.dout == 'ch6':
        data = file_blob(a, decode=64)
        keys = solve_block_keys(data)
        for keysize, hamdist, key in keys:
            print()
            print((keysize, hamdist, key))
            print(xor_cycle(data, key))

    if args.dout == 'ch7':
        blob = file_lines(a, decode=64)
        print(aes_ecb_decode(blob, 'YELLOW SUBMARINE'.encode()).decode())


if __name__ == '__main__':
    doctest.testmod()
    main()
