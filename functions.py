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
    return padded_mess


def process(padded_mess):
    """ input: padded message (type: bytearray)
        output: hashed message (type: string) """
    global initial_hash_values
    h0, h1, h2, h3, h4, h5, h6, h7 = initial_hash_values
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
