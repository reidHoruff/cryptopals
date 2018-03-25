import argparse as ap
import base64
from itertools import cycle
from functools import reduce
import doctest

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
            key, score, decoded = best_english_xor_decode(trans)
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


def best_english_xor_decode(a: bytes) -> tuple:
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

def find_best_english_decode(data: list) -> tuple:
    return tsort(map(best_english_xor_decode, data, reverse=True), 1)[0]

def file_lines(fname: str, decode=16) -> list:
    with open(fname) as f:
        lines = [line.strip() for line in f.readlines()]
        if decode is None:
            return [line.encode() for line in lines]
        if decode == 16:
            return [from_hex_str(line) for line in lines]

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

