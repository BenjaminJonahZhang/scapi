from __future__ import with_statement

import sys
from Crypto.Cipher import AES

def pack_into_char(bit_array):
    if len(bit_array) != 8:
        raise ValueError
    return chr(sum([2**(7-i) for i in xrange(8) if bit_array[i]]))

def get_byte_string(bits):
    return "".join([pack_into_char(bits[i:i+8]) for i in range(0, len(bits), 8)])

def main():
    if len(sys.argv) != 2:
        print "usage: python print_output.py [output_file]"
    
    filename = sys.argv[1]
    with open(filename, "rb") as f:
        lines = f.readlines()
        bits = [int(b) for b in lines]
        output = get_byte_string(bits)
    
    print [hex(ord(byte)) for byte in output]

if __name__ == "__main__":
    main()
