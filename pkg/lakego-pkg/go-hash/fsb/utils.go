package fsb

import (
    "encoding/binary"
)

// Convert a byte slice to a uint32 slice
func bytesToUints(b []byte) []uint32 {
    size := len(b) / 4
    dst := make([]uint32, size)

    for i := 0; i < size; i++ {
        j := i * 4

        dst[i] = binary.BigEndian.Uint32(b[j:])
    }

    return dst
}

// Convert a uint32 slice to a byte slice
func uintsToBytes(w []uint32) []byte {
    size := len(w) * 4
    dst := make([]byte, size)

    for i := 0; i < len(w); i++ {
        j := i * 4

        binary.BigEndian.PutUint32(dst[j:], w[i])
    }

    return dst
}

func LUI(a uint32) int {
    return int(a - 1) / (4 << 3) + 1
}

func logarithm(a uint32) int {
    var i int
    for i = 0; i < 32; i++ {
        if a == uint32(1 << i) {
            return i
        }
    }

    return -1
}

