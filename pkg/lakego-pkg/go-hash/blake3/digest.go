package blake3

const (
    // The size of blake3 hash in bytes.
    Size = 32

    // The block size of the hash algorithm in bytes.
    BlockSize = 64
)

type digest struct {
    key          [8]uint32
    chunk        *chunkState
    cv_stack_len uint8
    cv_stack     [(BLAKE3_MAX_DEPTH + 1) * BLAKE3_OUT_LEN]byte

    hs int
}

func newDigest(key [8]uint32, flags uint8, hs int) *digest {
    d := new(digest)
    d.key = key
    d.chunk = newChunkState(key, flags)
    d.hs = hs
    d.Reset()

    return d
}

// Reset resets the state of digest. It leaves salt intact.
func (d *digest) Reset() {
    d.chunk.reset(d.key, 0)
    d.cv_stack = [(BLAKE3_MAX_DEPTH + 1) * BLAKE3_OUT_LEN]byte{}
    d.cv_stack_len = 0
}

func (d *digest) Size() int {
    return d.hs
}

func (d *digest) BlockSize() int {
    return BlockSize
}

func (d *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    input_len := len(p)

    if input_len == 0 {
        return
    }

    input_bytes := p

    if d.chunk.length() > 0 {
        var take int = BLAKE3_CHUNK_LEN - d.chunk.length()
        if take > input_len {
            take = input_len;
        }

        d.chunk.update(input_bytes[:take])
        input_bytes = input_bytes[take:]
        input_len -= take

        if input_len > 0 {
            output := d.chunk.output()

            var chunk_cv [32]byte
            output.chaining_value(&chunk_cv)
            d.push_cv(chunk_cv, d.chunk.chunk_counter)
            d.chunk.reset(d.key, d.chunk.chunk_counter + 1)
        } else {
            return
        }
    }

    var tmp_cv [BLAKE3_OUT_LEN]byte

    for input_len > BLAKE3_CHUNK_LEN {
        var subtree_len int = int(round_down_to_power_of_2(uint64(input_len)))
        var count_so_far uint64 = d.chunk.chunk_counter * BLAKE3_CHUNK_LEN

        for ((uint64(subtree_len - 1)) & count_so_far) != 0 {
            subtree_len /= 2
        }

        var subtree_chunks uint64 = uint64(subtree_len) / BLAKE3_CHUNK_LEN
        if subtree_len <= BLAKE3_CHUNK_LEN {
            chunk_state := newChunkState(d.key, d.chunk.flags)
            chunk_state.chunk_counter = d.chunk.chunk_counter
            chunk_state.update(input_bytes[:subtree_len])

            output := chunk_state.output()
            var cv [BLAKE3_OUT_LEN]byte
            output.chaining_value(&cv)
            d.push_cv(cv, chunk_state.chunk_counter)
        } else {
            var cv_pair [2 * BLAKE3_OUT_LEN]byte
            cv_pair = compress_subtree_to_parent_node(
                input_bytes[:subtree_len],
                d.key,
                d.chunk.chunk_counter,
                d.chunk.flags,
            )

            copy(tmp_cv[:], cv_pair[:])
            d.push_cv(tmp_cv, d.chunk.chunk_counter)

            copy(tmp_cv[:], cv_pair[BLAKE3_OUT_LEN:])
            d.push_cv(tmp_cv, d.chunk.chunk_counter + (subtree_chunks / 2))
        }

        d.chunk.chunk_counter += subtree_chunks
        input_bytes = input_bytes[subtree_len:]
        input_len -= subtree_len
    }

    if input_len > 0 {
        d.chunk.update(input_bytes[:input_len])
        d.merge_cv_stack(d.chunk.chunk_counter)
    }

    return
}

// Sum returns the checksum.
func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d0 so that caller can keep writing and summing.
    d0 := *d
    sum := d0.checkSum()

    return append(in, sum[:]...)
}

func (d *digest) checkSum() (out []byte) {
    out = make([]byte, d.hs)
    d.finalize_seek(0, out)

    return
}

func (d *digest) finalize_seek(seek uint64, out []byte) {
    out_len := len(out)

    if out_len == 0 {
        return
    }

    if d.cv_stack_len == 0 {
        output := d.chunk.output()
        output.root_bytes(seek, out, out_len)
        return
    }

    var outbuf output
    var cvs_remaining int
    if d.chunk.length() > 0 {
        cvs_remaining = int(d.cv_stack_len)
        outbuf = d.chunk.output()
    } else {
        cvs_remaining = int(d.cv_stack_len) - 2
        var tmp [BLAKE3_BLOCK_LEN]byte
        copy(tmp[:], d.cv_stack[cvs_remaining * 32:])
        outbuf = parent_output(
            tmp,
            d.key,
            d.chunk.flags,
        )
    }

    var tmp [32]byte

    for cvs_remaining > 0 {
        cvs_remaining -= 1
        var parent_block [BLAKE3_BLOCK_LEN]byte

        copy(parent_block[:], d.cv_stack[cvs_remaining * 32 : cvs_remaining * 32 + 32])

        outbuf.chaining_value(&tmp)
        copy(parent_block[32:], tmp[:])

        outbuf = parent_output(parent_block, d.key, d.chunk.flags)
    }

    outbuf.root_bytes(seek, out, out_len)
}

func (d *digest) merge_cv_stack(total_len uint64) {
    post_merge_stack_len := int(popcnt(total_len))

    var parent_node [BLAKE3_BLOCK_LEN]byte
    for int(d.cv_stack_len) > post_merge_stack_len {
        copy(parent_node[:], d.cv_stack[(d.cv_stack_len - 2) * BLAKE3_OUT_LEN:])

        output := parent_output(parent_node, d.key, d.chunk.flags)
        var cv [32]byte
        output.chaining_value(&cv)

        copy(d.cv_stack[(d.cv_stack_len - 2) * BLAKE3_OUT_LEN:(d.cv_stack_len - 2) * BLAKE3_OUT_LEN+BLAKE3_BLOCK_LEN], cv[:])

        d.cv_stack_len -= 1
    }
}

func (d *digest) push_cv(
    new_cv [BLAKE3_OUT_LEN]byte,
    chunk_counter uint64,
) {
    d.merge_cv_stack(chunk_counter)
    copy(d.cv_stack[d.cv_stack_len * BLAKE3_OUT_LEN:], new_cv[:BLAKE3_OUT_LEN])
    d.cv_stack_len += 1
}
