package blake512

import (
    "errors"
    "encoding/binary"
)

const (
    chunk         = 128
    magic         = "blake512\x03"
    marshaledSize = len(magic) + 4*8 + chunk + 8 + 8*8 + 2*8
)

func (d *digest) MarshalBinary() ([]byte, error) {
    b := make([]byte, 0, marshaledSize)
    b = append(b, magic...)

    b = appendUint64(b, d.s[0])
    b = appendUint64(b, d.s[1])
    b = appendUint64(b, d.s[2])
    b = appendUint64(b, d.s[3])

    b = append(b, d.x[:d.nx]...)

    b = b[:len(b) + len(d.x) - int(d.nx)]
    b = appendUint64(b, d.len)

    b = appendUint64(b, d.h[0])
    b = appendUint64(b, d.h[1])
    b = appendUint64(b, d.h[2])
    b = appendUint64(b, d.h[3])
    b = appendUint64(b, d.h[4])
    b = appendUint64(b, d.h[5])
    b = appendUint64(b, d.h[6])
    b = appendUint64(b, d.h[7])

    b = appendUint64(b, d.t[0])
    b = appendUint64(b, d.t[1])

    return b, nil
}

func (d *digest) UnmarshalBinary(b []byte) error {
    if len(b) < len(magic) || (string(b[:len(magic)]) != magic) {
        return errors.New("go-hash/blake512: invalid hash state identifier")
    }

    if len(b) != marshaledSize {
        return errors.New("go-hash/blake512: invalid hash state size")
    }

    b = b[len(magic):]

    b, d.s[0] = consumeUint64(b)
    b, d.s[1] = consumeUint64(b)
    b, d.s[2] = consumeUint64(b)
    b, d.s[3] = consumeUint64(b)

    b = b[copy(d.x[:], b):]

    var length uint64
    b, length = consumeUint64(b)

    d.nx = int(length % chunk)
    d.len = length

    b, d.h[0] = consumeUint64(b)
    b, d.h[1] = consumeUint64(b)
    b, d.h[2] = consumeUint64(b)
    b, d.h[3] = consumeUint64(b)
    b, d.h[4] = consumeUint64(b)
    b, d.h[5] = consumeUint64(b)
    b, d.h[6] = consumeUint64(b)
    b, d.h[7] = consumeUint64(b)

    b, d.t[0] = consumeUint64(b)
    b, d.t[1] = consumeUint64(b)

    return nil
}

func appendUint64(b []byte, x uint64) []byte {
    var a [8]byte
    binary.BigEndian.PutUint64(a[:], x)
    return append(b, a[:]...)
}

func consumeUint64(b []byte) ([]byte, uint64) {
    _ = b[7]

    x := uint64(b[7])       |
         uint64(b[6]) <<  8 |
         uint64(b[5]) << 16 |
         uint64(b[4]) << 24 |
         uint64(b[3]) << 32 |
         uint64(b[2]) << 40 |
         uint64(b[1]) << 48 |
         uint64(b[0]) << 56

    return b[8:], x
}
