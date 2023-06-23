package asn1

// FLAG

// A Flag accepts any data and is set to true if present.
type Flag bool

type boolEncoder bool

func NewBoolEncoder(d bool) boolEncoder {
    i := boolEncoder(d)

    return i
}

func NewBoolEncoderWithInt(d int) boolEncoder {
    i := boolEncoder(false)

    if d != 0 {
        i = boolEncoder(true)
    }

    return i
}

func (b boolEncoder) length() int {
    return 1
}

func (e boolEncoder) encode() ([]byte, error) {
    if e {
        return []byte{0xff}, nil
    }

    return []byte{0x00}, nil
}
