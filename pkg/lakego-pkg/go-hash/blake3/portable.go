package blake3

func compress_pre(
    state     *[16]uint32,
    cv        [8]uint32,
    block     [BLAKE3_BLOCK_LEN]byte,
    block_len uint8,
    counter   uint64,
    flags     uint8,
) {
    var block_words [16]uint32
    block_words[0] = getu32(block[4 * 0:])
    block_words[1] = getu32(block[4 * 1:])
    block_words[2] = getu32(block[4 * 2:])
    block_words[3] = getu32(block[4 * 3:])
    block_words[4] = getu32(block[4 * 4:])
    block_words[5] = getu32(block[4 * 5:])
    block_words[6] = getu32(block[4 * 6:])
    block_words[7] = getu32(block[4 * 7:])
    block_words[8] = getu32(block[4 * 8:])
    block_words[9] = getu32(block[4 * 9:])
    block_words[10] = getu32(block[4 * 10:])
    block_words[11] = getu32(block[4 * 11:])
    block_words[12] = getu32(block[4 * 12:])
    block_words[13] = getu32(block[4 * 13:])
    block_words[14] = getu32(block[4 * 14:])
    block_words[15] = getu32(block[4 * 15:])

    state[0] = cv[0]
    state[1] = cv[1]
    state[2] = cv[2]
    state[3] = cv[3]
    state[4] = cv[4]
    state[5] = cv[5]
    state[6] = cv[6]
    state[7] = cv[7]
    state[8] = iv[0]
    state[9] = iv[1]
    state[10] = iv[2]
    state[11] = iv[3]
    state[12] = counter_low(counter)
    state[13] = counter_high(counter)
    state[14] = uint32(block_len)
    state[15] = uint32(flags)

    round_fn(state, block_words, 0)
    round_fn(state, block_words, 1)
    round_fn(state, block_words, 2)
    round_fn(state, block_words, 3)
    round_fn(state, block_words, 4)
    round_fn(state, block_words, 5)
    round_fn(state, block_words, 6)
}

func blake3_compress_in_place(
    cv        *[8]uint32,
    block     [BLAKE3_BLOCK_LEN]byte,
    block_len uint8,
    counter   uint64,
    flags     uint8,
) {
    var state [16]uint32
    compress_pre(&state, *cv, block, block_len, counter, flags)

    cv[0] = state[0] ^ state[8]
    cv[1] = state[1] ^ state[9]
    cv[2] = state[2] ^ state[10]
    cv[3] = state[3] ^ state[11]
    cv[4] = state[4] ^ state[12]
    cv[5] = state[5] ^ state[13]
    cv[6] = state[6] ^ state[14]
    cv[7] = state[7] ^ state[15]
}

func blake3_compress_xof(
    cv        [8]uint32,
    block     [BLAKE3_BLOCK_LEN]byte,
    block_len uint8,
    counter   uint64,
    flags     uint8,
    out       *[64]byte,
) {
    var state [16]uint32
    compress_pre(&state, cv, block, block_len, counter, flags)

    putu32(out[0 * 4:], state[0] ^ state[8])
    putu32(out[1 * 4:], state[1] ^ state[9])
    putu32(out[2 * 4:], state[2] ^ state[10])
    putu32(out[3 * 4:], state[3] ^ state[11])
    putu32(out[4 * 4:], state[4] ^ state[12])
    putu32(out[5 * 4:], state[5] ^ state[13])
    putu32(out[6 * 4:], state[6] ^ state[14])
    putu32(out[7 * 4:], state[7] ^ state[15])
    putu32(out[8 * 4:], state[8] ^ cv[0])
    putu32(out[9 * 4:], state[9] ^ cv[1])
    putu32(out[10 * 4:], state[10] ^ cv[2])
    putu32(out[11 * 4:], state[11] ^ cv[3])
    putu32(out[12 * 4:], state[12] ^ cv[4])
    putu32(out[13 * 4:], state[13] ^ cv[5])
    putu32(out[14 * 4:], state[14] ^ cv[6])
    putu32(out[15 * 4:], state[15] ^ cv[7])
}

func hash_one(
    input       []byte,
    blocks      int,
    key         [8]uint32,
    counter     uint64,
    flags       uint8,
    flags_start uint8,
    flags_end   uint8,
) (out [BLAKE3_OUT_LEN]byte) {
    var cv [8]uint32
    copy(cv[:], key[:])

    var block_flags byte = flags | flags_start
    var block [BLAKE3_BLOCK_LEN]byte

    var i int = 0
    for blocks > 0 {
        if blocks == 1 {
            block_flags |= flags_end
        }

        copy(block[:], input[i*BLAKE3_BLOCK_LEN:])

        blake3_compress_in_place(
            &cv,
            block,
            BLAKE3_BLOCK_LEN,
            counter,
            block_flags,
        )

        i++

        blocks -= 1
        block_flags = flags
    }

    buf := uint32sToBytes(cv[:])
    copy(out[:], buf)

    return
}

func blake3_hash_many(
    inputs            [][]byte,
    num_inputs        int,
    blocks            int,
    key               [8]uint32,
    counter           uint64,
    increment_counter bool,
    flags             uint8,
    flags_start       uint8,
    flags_end         uint8,
) (out []byte) {
    var block [BLAKE3_OUT_LEN]byte

    var i int = 0
    for num_inputs > 0 {
        block = hash_one(
            inputs[i],
            blocks,
            key,
            counter,
            flags,
            flags_start,
            flags_end,
        )

        if increment_counter {
            counter += 1
        }

        i += 1
        num_inputs -= 1

        out = append(out, block[:]...)
    }

    return
}
