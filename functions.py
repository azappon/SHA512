# Constants

h0 = 0x6a09e667f3bcc908
h1 = 0xbb67ae8584caa73b
h2 = 0x3c6ef372fe94f82b
h3 = 0xa54ff53a5f1d36f1
h4 = 0x510e527fade682d1
h5 = 0x9b05688c2b3e6c1f
h6 = 0x1f83d9abfb41bd6b
h7 = 0x5be0cd19137e2179
        
     # the round constants are based on the cube roots of the first 80 primes (2..4091):
k = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
     0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
     0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
     0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
     0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
     0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
     0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
     0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
     0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
     0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
     0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
     0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
     0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
     0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
     0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
     0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]


# Functions

def rotate_right(number, amount):
    return (number >> amount) | (number << (32 - amount))


def rotate_left(number, amount):
    return (number << amount) | (number >> (32 - amount))


def shift_left(number, amount):
    return number << amount


def shift_right(number, amount):
    return number >> amount


def padding(message):
    """ input: plaintext (type: string)
        <original message of length L> 1 <K zeros> <L as 64 bit integer>
                            output: padded message (type: bytearray) """
    # object bytearray keeps same length of the original string
    # https://docs.python.org/3/library/stdtypes.html#bytearray
    mess = bytearray(message, encoding='utf8')
    # message length in bits
    mess_length = (len(mess) * 8) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    # message length in bytes
    # https://docs.python.org/3/library/stdtypes.html#int.to_bytes
    mess_length_bytes = mess_length.to_bytes(8, byteorder='big')
    # append single '1' bit
    mess.append(0x80)
    # append K zeros so that after adding the 64 bit length the message
    # will be 512 (or a multiple) bit long
    while (len(mess) + len(mess_length_bytes)) % 128 != 0:
        mess.append(0)
    # adding the 64 bit length of the original message
    mess += mess_length_bytes
    assert len(mess) % 128 == 0, f"Padding error! Length of message is: {len(mess)}"
    return mess


def process(padded_mess):
    """ input: padded message (type: bytearray)
        output: hashed message (type: string) """
    global h0, h1, h2, h3, h4, h5, h6, h7
    # process the message in successive 1024-bit = 128-bytes chunks:
    for chunk_index in range(0, len(padded_mess), 128):
        chunks = padded_mess[chunk_index: chunk_index + 128]
        # the initial values in w[0..63] don't matter: choose to zero them
        w = [0 for i in range(128)]
        # break chunk into sixteen 64-bit = 8-bytes words w[i], 0 ≤ i ≤ 15
        for i in range(16):
            w[i] = int.from_bytes(chunks[8 * i: 8 * i + 8], byteorder='big')
        # extend the first 16 words into the remaining 64 words w[16..79] of the message schedule array:
        for i in range(16, 80):
            s0 = (rotate_right(w[i - 15], 1) ^ rotate_right(w[i - 15], 8) ^ shift_right(w[i - 15], 7)) & 0xFFFFFFFFFFFFFFFF
            s1 = (rotate_right(w[i - 2], 19) ^ rotate_right(w[i - 2], 61) ^ shift_right(w[i - 2], 6)) & 0xFFFFFFFFFFFFFFFF
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFFFFFFFFFF
        # initialize hash value for this chunk
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        # main loop: https://tools.ietf.org/html/rfc6234
        for i in range(80):
            s1 = (rotate_right(e, 14) ^ rotate_right(e, 18) ^ rotate_right(e, 41)) & 0xFFFFFFFFFFFFFFFF
            ch = ((e & f) ^ ((~e) & g)) & 0xFFFFFFFFFFFFFFFF
            temp1 = (h + s1 + ch + k[i] + w[i]) & 0xFFFFFFFFFFFFFFFF
            s0 = (rotate_right(a, 28) ^ rotate_right(a, 34) ^ rotate_right(a, 39)) & 0xFFFFFFFFFFFFFFFF
            maj = ((a & b) ^ (a & c) ^ (b & c)) & 0xFFFFFFFFFFFFFFFF
            temp2 = (s0 + maj) & 0xFFFFFFFFFFFFFFFF

            # rotate the 8 variables
            a = (temp1 + temp2) & 0xFFFFFFFFFFFFFFFF
            e = (d + temp1) & 0xFFFFFFFFFFFFFFFF
            b, c, d, f, g, h = a, b, c, e, f, g

        # add this chunk's hash to result so far:
        h0_f = (h0 + a) & 0xFFFFFFFFFFFFFFFF
        h1_f = (h1 + b) & 0xFFFFFFFFFFFFFFFF
        h2_f = (h2 + c) & 0xFFFFFFFFFFFFFFFF
        h3_f = (h3 + d) & 0xFFFFFFFFFFFFFFFF
        h4_f = (h4 + e) & 0xFFFFFFFFFFFFFFFF
        h5_f = (h5 + f) & 0xFFFFFFFFFFFFFFFF
        h6_f = (h6 + g) & 0xFFFFFFFFFFFFFFFF
        h7_f = (h7 + h) & 0xFFFFFFFFFFFFFFFF

    # final hash value (big-endian)
    return '%08x%08x%08x%08x%08x%08x%08x%08x' % (h0_f, h1_f, h2_f, h3_f, h4_f, h5_f, h6_f, h7_f)
