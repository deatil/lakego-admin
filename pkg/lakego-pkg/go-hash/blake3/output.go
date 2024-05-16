package blake3

type output struct {
    input_cv  [8]uint32
    counter   uint64
    block     [BLAKE3_BLOCK_LEN]byte
    block_len uint8
    flags     uint8
}

func newOutput(
    input_cv  [8]uint32,
    block     [BLAKE3_BLOCK_LEN]byte,
    block_len uint8,
    counter   uint64,
    flags     uint8,
) output {
    var ret output
    copy(ret.input_cv[:], input_cv[:])
    copy(ret.block[:], block[:])

    ret.block_len = block_len
    ret.counter = counter
    ret.flags = flags

    return ret
}

func (o *output) chainingValue(cv *[32]byte) {
    var cv_words [8]uint32
    copy(cv_words[:], o.input_cv[:])

    blake3_compress_in_place(
        &cv_words,
        o.block,
        o.block_len,
        o.counter,
        o.flags,
    )

    buf := uint32sToBytes(cv_words[:])
    copy(cv[:], buf)
}

func (o *output) rootBytes(seek uint64, out []byte, out_len int) {
    var output_block_counter uint64 = seek / 64;
    var offset_within_block int = int(seek % 64)
    var wide_buf [64]byte

    for out_len > 0 {
        blake3_compress_xof(
            o.input_cv,
            o.block,
            o.block_len,
            output_block_counter,
            o.flags | ROOT,
            &wide_buf,
        )

        var available_bytes int = 64 - offset_within_block
        var memcpy_len int

        if out_len > available_bytes {
            memcpy_len = available_bytes
        } else {
            memcpy_len = out_len
        }

        copy(out[:], wide_buf[offset_within_block:memcpy_len])

        out = out[memcpy_len:]
        out_len -= memcpy_len

        output_block_counter += 1
        offset_within_block = 0
    }
}
