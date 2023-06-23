package asn1

import (
    "reflect"
)

type BitString struct {
    Bytes     []byte // bits packed into bytes.
    BitLength int    // length in bits.
}

// At returns the bit at the given index. If the index is out of range it
// returns 0.
func (b BitString) At(i int) int {
    if i < 0 || i >= b.BitLength {
        return 0
    }
    x := i / 8
    y := 7 - uint(i%8)
    return int(b.Bytes[x]>>y) & 1
}

// RightAlign returns a slice where the padding bits are at the beginning. The
// slice may share memory with the BitString.
func (b BitString) RightAlign() []byte {
    shift := uint(8 - (b.BitLength % 8))
    if shift == 8 || len(b.Bytes) == 0 {
        return b.Bytes
    }

    a := make([]byte, len(b.Bytes))
    a[0] = b.Bytes[0] >> shift
    for i := 1; i < len(b.Bytes); i++ {
        a[i] = b.Bytes[i-1] << (8 - shift)
        a[i] |= b.Bytes[i] >> shift
    }

    return a
}

var bitStringType = reflect.TypeOf(BitString{})

type bitStringEncoder BitString

func (b bitStringEncoder) length() int {
    return len(b.Bytes) + 1
}

func (b bitStringEncoder) encode() ([]byte, error) {
    buf := make([]byte, len(b.Bytes)+1)
    buf[0] = byte((8 - b.BitLength%8) % 8)
    copy(buf[1:], b.Bytes)

    return buf, nil
}
