import argparse as ap
import base64
from itertools import cycle
from functools import reduce
import doctest
import pyaes
from random import randint

freq = b'etaoinshrdlcumwfgypbvkjxqz'
engl = b' ,.\'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ:\n'
YS = b'YELLOW SUBMARINE'


def random_bytes(n: int) -> bytes:
    """
    >>> len(random_bytes(3000))
    3000
    >>> len(random_bytes(1))
    1
    """
    return bytes([randint(0, 255) for _ in range(n)])


def is_repeating(a: bytes) -> bool:
    """
    >>> is_repeating(b'ii')
    True
    >>> is_repeating(b'iii')
    False
    >>> is_repeating(b'abac')
    False
    """
    if len(a) % 2 == 1:
        return False

    h = int(len(a)/2)

    return a[:h] == a[h:]


def inc_blob(n: int) -> bytes:
    """
    Blob of incrementing byte values of len N.

    >>> inc_blob(1)
    b'\\x00'
    >>> inc_blob(3)
    b'\\x00\\x01\\x02'
    >>> len(inc_blob(16))
    16
    >>> len(inc_blob(1000))
    1000
    """
    return bytes([i % 256 for i in range(n)])


def english_score(a: bytes) -> int:
    """
    How many english characters?

    >>> english_score(b'hel\x0flo!')
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
    Divides input into chunks of size N.
    Last chunk len will be <= N

    >>> list(divide(b'abcde', 2))
    [b'ab', b'cd', b'e']
    >>> list(divide(b'abcde', 100))
    [b'abcde']
    >>> list(divide(b'abcde', 5))
    [b'abcde']
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
        if not is_repeating(key_parts):
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
    """
    Cyclically xor key over data.
    """
    return bytes([x^y for x, y in zip(data, cycle(key))])


def xor_key_w_most_engl(a: bytes) -> tuple:
    """
    Find the single byte Xor key which produces the
    most english characters.

    """
    max_score = 0
    winner = None
    for key in range(256):
        decoded = xor_cycle(a, bytes([key]))
        score = english_score(decoded)
        if score >= max_score:
            max_score = score
            if score == len(decoded):
                decoded = decoded.decode()
            winner = (key, score, decoded)

    return winner


def tsort(l: list, index: int, reverse=False) -> list:
    """
    Sorts a list of tuples by an column in that tuple.
    """
    return sorted(l, key=lambda w: w[index], reverse=reverse)


def file_lines(fname: str, decode=16) -> list:
    with open(fname) as f:
        lines = [line.strip() for line in f.readlines()]
        if decode is None:
            return [line.encode() for line in lines]
        if decode == 16:
            return [from_hex_str(line) for line in lines]

def b64_file(fname: str) -> bytes:
    with open(fname) as f:
        lines = [line.strip() for line in f.readlines()]
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
    """
    >>> from_b64('AAAA')
    b'\\x00\\x00\\x00'
    """
    return base64.b64decode(a)

def to_hex(a: bytes) -> str:
    """
    >>> to_hex(b'AA')
    '4141'
    """
    return a.hex()

def to_b64(a: bytes) -> str:
    return base64.b64encode(a)

def plist(l: list):
    for r in l:
        print(r)


def aes_ecb_dec(blob: bytes, key: bytes) -> bytes:
    """
    Decodes the blob in 16 bytes chunks.
    Returns the concatination of all 16 byte results.
    """
    aes = pyaes.AESModeOfOperationECB(key)
    comb = b''

    for b in divide(blob, 16):
        comb += aes.decrypt(b)

    return comb


def aes_ecb_enc(blob: bytes, key: bytes) -> bytes:
    """
    Encodes the blob in 16 bytes chunks.
    Returns the concatination of all 16 byte results.

    >>> a = aes_ecb_enc(pad_to_len(b'horuff', 16), YS)
    >>> b = aes_ecb_dec(a, YS)
    >>> b == pad_to_len(b'horuff', 16)
    True
    """

    aes = pyaes.AESModeOfOperationECB(key)
    comb = b''

    for chunk in divide(pad_to_nearest(blob, 16), 16):
        comb += aes.encrypt(chunk)

    return comb


def aes_cbc_enc(blob: bytes, key: bytes, rand_iv=False) -> bytes:
    """
    >>> out = aes_cbc_enc(inc_blob(16), inc_blob(16))
    >>> len(out)
    16
    >>> out = aes_cbc_enc(inc_blob(19), inc_blob(16))
    >>> len(out)
    32
    """

    previous = bytes([0] * 16)

    if rand_iv:
        previous = random_bytes(16)

    out = b''

    for chunk in divide(pad_to_nearest(blob, 16), 16):
        previous = aes_ecb_enc(xor_cycle(chunk, previous), key)
        out += previous

    return out


def aes_cbc_dec(blob: bytes, key: bytes) -> bytes:
    """
    >>> encoded = aes_cbc_enc(inc_blob(128), inc_blob(16))
    >>> decoded = aes_cbc_dec(encoded, inc_blob(16))
    >>> decoded == inc_blob(128)
    True
    """

    assert len(blob) % 16 == 0

    previous = bytes([0] * 16)
    out = b''

    for chunk in divide(blob, 16):
        decoded = xor_cycle(aes_ecb_dec(chunk, key), previous)
        previous = chunk
        out += decoded

    return out


def enc_oracle(data: bytes) -> bytes:
    """
    Does random enc.

    >>> a = enc_oracle(random_bytes(99))
    >>> a = enc_oracle(random_bytes(99))
    >>> a = enc_oracle(random_bytes(99))
    >>> a = enc_oracle(random_bytes(99))
    >>> a = enc_oracle(random_bytes(99))
    >>> a = enc_oracle(random_bytes(9999))
    """
    rand_key = random_bytes(16)

    data = random_bytes(randint(5, 10)) + data + random_bytes(randint(5, 10))

    if randint(0, 1) == 0:
        return 'ECB', aes_ecb_enc(data, rand_key)

    else:
        return 'CBC', aes_cbc_enc(data, rand_key)

def detect_oracle():
    """

    Creates a packet to be encoded by the oracle.
    Asserts that the detected encryption scheme was correct.

    Method:
        create packet of incrementing values % block size (16)
        see if the second and third block of the oracle output are identical.
        (the first block contains random data)

    >>> for _ in range(1000):
    ...   detect_oracle()
    """

    inp = bytes([i % 16 for i in range(48)])
    res = enc_oracle(inp)
    mode = res[0]
    ignore, a, b, *_ = divide(res[1], 16)

    if a == b:
        assert mode == 'ECB'
    else:
        assert mode == 'CBC'


def find_repeat(blob: bytes, size: int) -> bool:
    """
    Are there duplicate N byte blocks in the blob?

    >>> find_repeat(b'abceeeabc', 3)
    b'abc'
    >>> find_repeat(b'abceeeabc', 4)
    False
    >>> find_repeat(b'aa', 1)
    b'a'
    """
    blocks = list(divide(blob, size))
    found = set()
    for block in blocks:
        if block in found:
            return block
        found.add(block)

    return False


def create_pad(n: int) -> bytes:
    """
    >>> to_hex(create_pad(1))
    '01'
    >>> to_hex(create_pad(5))
    '0505050505'
    >>> to_hex(create_pad(0))
    ''
    """
    return bytes([n for i in range(n)])


def pad_to_len(a: bytes, n: int) -> bytes:
    """
    >>> pad_to_len(YS, 20)
    b'YELLOW SUBMARINE\\x04\\x04\\x04\\x04'
    """
    return a + create_pad(n - len(a))

def pad_to_nearest(a: bytes, n: int) -> bytes:
    """
    Pad to a length modulus.
    ie, pad the the next multiple of N.

    >>> pad_to_nearest(b'foo', 2)
    b'foo\\x01'
    >>> pad_to_nearest(b'foo', 5)
    b'foo\\x02\\x02'
    >>> pad_to_nearest(b'12345', 4)
    b'12345\\x03\\x03\\x03'
    >>> pad_to_nearest(b'12345', 5)
    b'12345'
    """
    if len(a) % n == 0:
        return a

    return a + create_pad(n - (len(a) % n))


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
        print(to_hex(xor_cycle(from_hex_str(a), from_hex_str(b))))

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
        print(to_hex(xor_cycle(data, key)))

    if args.dout == 'ch6':
        data = file_blob(a, decode=64)
        keys = solve_block_keys(data)
        for keysize, hamdist, key in keys:
            print()
            print((keysize, hamdist, key))
            print(xor_cycle(data, key))

    if args.dout == 'ch7':
        blob = b64_file(a)
        print(aes_ecb_dec(blob, YS).decode())

    if args.dout == 'ch8':
        for dat in file_lines(a, decode=16):
            r = find_repeat(dat, 16)
            if r:
                print(r)

    if args.dout == 'ch10':
        blob = b64_file(a)
        print(aes_cbc_dec(blob, YS))


if __name__ == '__main__':
    doctest.testmod()
    main()
