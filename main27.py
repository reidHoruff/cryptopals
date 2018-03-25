from Crypto.Cipher import AES
import argparse as ap
import base64

def file_lines(fname: str, decode=16) -> list:
    with open(fname) as f:
        lines = [line.strip() for line in f.readlines()]
        if decode is None:
            return [line.encode() for line in lines]
        if decode == 16:
            return [from_hex_str(line) for line in lines]

def main():
    parser = ap.ArgumentParser()
    parser.add_argument('--a', type=str)
    parser.add_argument('--b', type=str)
    parser.add_argument('--dout', type=str)
    args = parser.parse_args()

    a = args.a
    b = args.b

    if args.dout == 'hex_xor':
        print(to_b16(xor_cycle(from_hex_str(a), from_hex_str(b))))

    if args.dout == 'decode_engl':
        data = from_hex_str(a)
        print(mostly_english(data))

    if args.dout == 'decode_engl_file':
        data = file_lines(a, decode=16)
        print(find_best_english_decode(data))

    if args.dout == 'encode':
        data = file_blob(a, decode=None)
        print(data)
        key = b.encode()
        print(to_b16(xor_cycle(data, key)))

    if args.dout == 'challenge6':
        data = file_blob(a, decode=64)
        keys = solve_block_keys(data)
        for keysize, hamdist, key in keys:
            print()
            print((keysize, hamdist, key))
            print(xor_cycle(data, key))

    if args.dout == 'challenge7':
        full = bytearray()
        for blob in file_lines(a, decode=64):
            full += blob



if __name__ == '__main__':
    doctest.testmod()
    main()
