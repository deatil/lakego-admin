package blake3

import (
    "math/bits"
    "encoding/binary"
)

func getu32(ptr []byte) uint32 {
    return binary.LittleEndian.Uint32(ptr)
}

func putu32(ptr []byte, a uint32) {
    binary.LittleEndian.PutUint32(ptr, a)
}

func bytesToUint32s(b []byte) []uint32 {
    size := len(b) / 4
    dst := make([]uint32, size)

    for i := 0; i < size; i++ {
        j := i * 4

        dst[i] = binary.LittleEndian.Uint32(b[j:])
    }

    return dst
}

func uint32sToBytes(w []uint32) []byte {
    size := len(w) * 4
    dst := make([]byte, size)

    for i := 0; i < len(w); i++ {
        j := i * 4

        binary.LittleEndian.PutUint32(dst[j:], w[i])
    }

    return dst
}

func highest_one(x uint64) uint {
    var c uint = 0

    if (x & 0xffffffff00000000) != 0 {
        x >>= 32
        c += 32
    }
    if (x & 0x00000000ffff0000) != 0 {
        x >>= 16
        c += 16
    }
    if (x & 0x000000000000ff00) != 0 {
        x >>= 8
        c += 8
    }
    if (x & 0x00000000000000f0) != 0 {
        x >>= 4
        c += 4
    }
    if (x & 0x000000000000000c) != 0 {
        x >>= 2
        c += 2
    }
    if (x & 0x0000000000000002) != 0 {
        c +=  1
    }

    return c
}

func popcnt(x uint64) uint {
    var count uint = 0

    for x != 0 {
        count += 1
        x &= x - 1
    }

    return count
}

func round_down_to_power_of_2(x uint64) uint64 {
  return uint64(1) << highest_one(x | 1)
}

func counter_low(counter uint64) uint32 {
    return uint32(counter)
}

func counter_high(counter uint64) uint32 {
  return uint32(counter >> 32)
}

func rotr32(x uint32, n int) uint32 {
    return bits.RotateLeft32(x, 32 - n)
}

func g(state *[16]uint32, a, b, c, d int, x, y uint32) {
    state[a] = state[a] + state[b] + x
    state[d] = rotr32(state[d] ^ state[a], 16)
    state[c] = state[c] + state[d]
    state[b] = rotr32(state[b] ^ state[c], 12)
    state[a] = state[a] + state[b] + y
    state[d] = rotr32(state[d] ^ state[a], 8)
    state[c] = state[c] + state[d]
    state[b] = rotr32(state[b] ^ state[c], 7)
}

func round_fn(state *[16]uint32, msg [16]uint32, round int) {
    // Select the message schedule based on the round.
    schedule := MSG_SCHEDULE[round]

    // Mix the columns.
    g(state, 0, 4, 8, 12, msg[schedule[0]], msg[schedule[1]])
    g(state, 1, 5, 9, 13, msg[schedule[2]], msg[schedule[3]])
    g(state, 2, 6, 10, 14, msg[schedule[4]], msg[schedule[5]])
    g(state, 3, 7, 11, 15, msg[schedule[6]], msg[schedule[7]])

    // Mix the rows.
    g(state, 0, 5, 10, 15, msg[schedule[8]], msg[schedule[9]])
    g(state, 1, 6, 11, 12, msg[schedule[10]], msg[schedule[11]])
    g(state, 2, 7, 8, 13, msg[schedule[12]], msg[schedule[13]])
    g(state, 3, 4, 9, 14, msg[schedule[14]], msg[schedule[15]])
}
