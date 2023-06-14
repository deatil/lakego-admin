package asn1

import (
    "fmt"
    "reflect"
)

type BitString struct {
    Bytes       []byte
    PaddingBits int
}

var bitStringType = reflect.TypeOf(BitString{})

func NewBitString(b []byte, paddingBits int) (BitString, error) {
    bitString := BitString{
        Bytes: b,
    }

    if paddingBits > 7 {
        return bitString, fmt.Errorf("too many padding bits: expecting <= 7, got: %d", paddingBits)
    }

    if len(b) == 0 && paddingBits != 0 {
        return bitString, fmt.Errorf("empty bit string, but got %d padding bits", paddingBits)
    }

    bitString.PaddingBits = paddingBits

    return bitString, nil
}

type bitStringEncoder BitString

func (e bitStringEncoder) encode() ([]byte, error) {
    buf := make([]byte, len(e.Bytes)+1)
    buf[0] = byte(e.PaddingBits)
    copy(buf[1:], e.Bytes)

    return buf, nil
}
