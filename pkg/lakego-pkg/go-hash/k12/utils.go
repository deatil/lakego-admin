package k12

import (
    "encoding/binary"
)

// Encodes the length of a value. It is used in the final padding of K12
func rightEncode(value uint64) []byte {
    var input [9]byte
    var offset int

    if value == 0 {
        offset = 8
    } else {
        binary.BigEndian.PutUint64(input[0:], value)
        for offset = 0; offset < 9; offset++ {
            if input[offset] != 0 {
                break
            }
        }
    }

    input[8] = byte(8 - offset)
    return input[offset:]
}
