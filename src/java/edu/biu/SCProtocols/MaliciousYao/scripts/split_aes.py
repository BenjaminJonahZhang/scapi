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
    if len(sys.argv) != 3:
        print "usage: python split_aes.py [input_file_P1] [input_file_P2]"
    filenames = [sys.argv[1], sys.argv[2]]

    inputs = []
    for filename in filenames:
        with open(filename, "rb") as f:
            lines = f.readlines()[1:] # we don't need the number of inputs
            bits = [int(b) for b in lines]
            party_input = get_byte_string(bits)
            inputs.append(party_input)

     
    aes = AES.new(inputs[0])
    ciphertext = aes.encrypt(inputs[1])
    print [hex(ord(byte)) for byte in ciphertext]

if __name__ == "__main__":
    main()
