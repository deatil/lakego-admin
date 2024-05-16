package blake3

// This struct is a private implementation detail. It has to be here because
// it's part of blake3_hasher below.
type chunkState struct {
    cv                [8]uint32
    chunk_counter     uint64
    buf               [BLAKE3_BLOCK_LEN]byte
    buf_len           uint8
    blocks_compressed uint8
    flags             uint8
}

func newChunkState(key [8]uint32, flags uint8) *chunkState {
    cs := new(chunkState)
    cs.cv = key
    cs.buf = [BLAKE3_BLOCK_LEN]byte{}
    cs.buf_len = 0
    cs.blocks_compressed = 0
    cs.flags = flags

    return cs
}

func (cs *chunkState) reset(key [8]uint32, chunk_counter uint64) {
    cs.cv = key
    cs.chunk_counter = chunk_counter
    cs.blocks_compressed = 0
    cs.buf = [BLAKE3_BLOCK_LEN]byte{}
    cs.buf_len = 0
}

func (cs *chunkState) length() int {
    return (BLAKE3_BLOCK_LEN * int(cs.blocks_compressed)) + (int(cs.buf_len))
}

func (cs *chunkState) fillBuf(input []byte) int {
    input_len := len(input)

    var take int = BLAKE3_BLOCK_LEN - int(cs.buf_len)
    if take > input_len {
        take = input_len
    }

    dest := cs.buf[int(cs.buf_len):]
    copy(dest[:take], input[:])

    cs.buf_len += uint8(take)
    return take
}

func (cs *chunkState) maybeStartFlag() uint8 {
    if cs.blocks_compressed == 0 {
        return CHUNK_START
    } else {
        return 0
    }
}

func (cs *chunkState) update(input []byte) {
    input_len := len(input)

    if cs.buf_len > 0 {
        var take int = cs.fillBuf(input)

        input = input[take:]
        input_len -= take

        if input_len > 0 {
            blake3_compress_in_place(
                &cs.cv,
                cs.buf,
                BLAKE3_BLOCK_LEN,
                cs.chunk_counter,
                cs.flags | cs.maybeStartFlag(),
            )

            cs.blocks_compressed += 1
            cs.buf_len = 0
            cs.buf = [BLAKE3_BLOCK_LEN]byte{}
        }
    }

    var tmp [BLAKE3_BLOCK_LEN]byte
    for input_len > BLAKE3_BLOCK_LEN {
        copy(tmp[:], input)
        blake3_compress_in_place(
            &cs.cv,
            tmp,
            BLAKE3_BLOCK_LEN,
            cs.chunk_counter,
            cs.flags | cs.maybeStartFlag(),
        )

        cs.blocks_compressed += 1

        input = input[BLAKE3_BLOCK_LEN:]
        input_len -= BLAKE3_BLOCK_LEN
    }

    var take int = cs.fillBuf(input)
    input = input[take:]
    input_len -= take
}

func (cs *chunkState) output() output {
    var block_flags uint8 = cs.flags | cs.maybeStartFlag() | CHUNK_END

    return newOutput(
        cs.cv, cs.buf,
        cs.buf_len,
        cs.chunk_counter,
        block_flags,
    )
}
