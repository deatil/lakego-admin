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

func (cs *chunkState) fill_buf(input []byte) int {
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

func (cs *chunkState) maybe_start_flag() uint8 {
    if cs.blocks_compressed == 0 {
        return CHUNK_START
    } else {
        return 0
    }
}

func (cs *chunkState) update(input []byte) {
    input_len := len(input)

    if cs.buf_len > 0 {
        var take int = cs.fill_buf(input)

        input = input[take:]
        input_len -= take

        if input_len > 0 {
            blake3_compress_in_place(
                &cs.cv,
                cs.buf,
                BLAKE3_BLOCK_LEN,
                cs.chunk_counter,
                cs.flags | cs.maybe_start_flag(),
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
            cs.flags | cs.maybe_start_flag(),
        )

        cs.blocks_compressed += 1

        input = input[BLAKE3_BLOCK_LEN:]
        input_len -= BLAKE3_BLOCK_LEN
    }

    var take int = cs.fill_buf(input)
    input = input[take:]
    input_len -= take
}

func (cs *chunkState) output() output {
    var block_flags uint8 = cs.flags | cs.maybe_start_flag() | CHUNK_END

    return newOutput(
        cs.cv, cs.buf,
        cs.buf_len,
        cs.chunk_counter,
        block_flags,
    )
}

func parent_output(block [BLAKE3_BLOCK_LEN]byte, key [8]uint32, flags uint8) output {
    return newOutput(key, block, BLAKE3_BLOCK_LEN, 0, flags | PARENT)
}

func left_len(content_len int) int {
    var full_chunks int = (content_len - 1) / BLAKE3_CHUNK_LEN
    return int(round_down_to_power_of_2(uint64(full_chunks))) * BLAKE3_CHUNK_LEN
}

func compress_chunks_parallel(
    input         []byte,
    key           [8]uint32,
    chunk_counter uint64,
    flags         uint8,
) (out []byte, array_len int) {
    input_len := len(input)

    var chunks_array [MAX_SIMD_DEGREE][]byte
    var input_position int = 0
    var chunks_array_len int = 0

    for (input_len - input_position) >= BLAKE3_CHUNK_LEN {
        chunks_array[chunks_array_len] = make([]byte, BLAKE3_CHUNK_LEN)
        copy(chunks_array[chunks_array_len], input[input_position:])

        input_position += BLAKE3_CHUNK_LEN
        chunks_array_len += 1
    }

    buf := blake3_hash_many(
        chunks_array[:],
        chunks_array_len,
        BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN,
        key,
        chunk_counter,
        true,
        flags,
        CHUNK_START,
        CHUNK_END,
    )

    out = append(out, buf...)

    if input_len > input_position {
        var counter uint64 = chunk_counter + uint64(chunks_array_len)
        chunk_state := newChunkState(key, flags)

        chunk_state.chunk_counter = counter
        chunk_state.update(input[input_position:])

        tmp := [32]byte{}

        output := chunk_state.output()
        output.chaining_value(&tmp);

        out = append(out, tmp[:]...)

        return out, chunks_array_len + 1
    } else {
        return out, chunks_array_len
    }
}

func compress_parents_parallel(
    child_chaining_values []byte,
    num_chaining_values   int,
    key                   [8]uint32,
    flags                 uint8,
) (out []byte, array_len int) {
    var parents_array [MAX_SIMD_DEGREE_OR_2][]byte
    var parents_array_len int = 0

    for (num_chaining_values - (2 * parents_array_len)) >= 2 {
        parents_array[parents_array_len] = make([]byte, 2 * BLAKE3_OUT_LEN)
        copy(parents_array[parents_array_len], child_chaining_values[2 * BLAKE3_OUT_LEN * parents_array_len:])
        parents_array_len += 1
    }

    buf := blake3_hash_many(
        parents_array[:],
        parents_array_len,
        1,
        key,
        0,
        false,
        flags | PARENT,
        0,
        0,
    )

    out = append(out, buf...)

    if num_chaining_values > 2 * parents_array_len {
        out = append(out, child_chaining_values[2 * parents_array_len * BLAKE3_OUT_LEN:2 * parents_array_len * BLAKE3_OUT_LEN+BLAKE3_OUT_LEN]...)
        return out, parents_array_len + 1
    } else {
        return out, parents_array_len
    }
}

func blake3_compress_subtree_wide(
    input         []byte,
    key           [8]uint32,
    chunk_counter uint64,
    flags         uint8,
) (out []byte, array_len int) {
    input_len := len(input)

    if input_len <= BLAKE3_CHUNK_LEN {
        return compress_chunks_parallel(
            input,
            key,
            chunk_counter,
            flags,
        )
    }

    var left_input_len int = left_len(input_len)
    var right_input_len int = input_len - left_input_len
    var right_input []byte = input[left_input_len:]
    var right_chunk_counter uint64 = chunk_counter + uint64(left_input_len / BLAKE3_CHUNK_LEN)

    var cv_array [2 * MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN]byte
    var degree int = 1
    if left_input_len > BLAKE3_CHUNK_LEN && degree == 1 {
        degree = 2
    }

    left_cvs, left_n := blake3_compress_subtree_wide(
        input[:left_input_len],
        key,
        chunk_counter,
        flags,
    )
    right_cvs, right_n := blake3_compress_subtree_wide(
        right_input[:right_input_len],
        key,
        right_chunk_counter,
        flags,
    )

    copy(cv_array[:], left_cvs)
    copy(cv_array[degree * BLAKE3_OUT_LEN:], right_cvs)

    if left_n == 1 {
        out = cv_array[:2 * BLAKE3_OUT_LEN]
        return out, 2
    }

    var num_chaining_values int = left_n + right_n
    return compress_parents_parallel(
        cv_array[:],
        num_chaining_values,
        key,
        flags,
    )
}

func compress_subtree_to_parent_node(
    input         []byte,
    key           [8]uint32,
    chunk_counter uint64,
    flags         uint8,
) (out [2 * BLAKE3_OUT_LEN]byte) {
    var cv_array [MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN]byte
    cv_array_tmp, num_cvs := blake3_compress_subtree_wide(
        input,
        key,
        chunk_counter,
        flags,
    )
    copy(cv_array[:], cv_array_tmp)

    var out_array [MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN / 2]byte
    var out_array_tmp []byte

    for num_cvs > 2 && num_cvs <= MAX_SIMD_DEGREE_OR_2 {
        out_array_tmp, num_cvs = compress_parents_parallel(cv_array[:], num_cvs, key, flags)
        copy(out_array[:], out_array_tmp)
        copy(cv_array[:], out_array[:num_cvs * BLAKE3_OUT_LEN])
    }

    copy(out[:], cv_array[:2 * BLAKE3_OUT_LEN])

    return
}

