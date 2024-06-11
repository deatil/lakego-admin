package blake256

import (
    "errors"
    "encoding/binary"
)

const (
    chunk         = 64
    magic         = "blake256\x03"
    marshaledSize = len(magic) + 4*4 + chunk + 8 + 8*4 + 8 + 1
)

func (d *digest) MarshalBinary() ([]byte, error) {
    b := make([]byte, 0, marshaledSize)
    b = append(b, magic...)

    b = appendUint32(b, d.s[0])
    b = appendUint32(b, d.s[1])
    b = appendUint32(b, d.s[2])
    b = appendUint32(b, d.s[3])

    b = append(b, d.x[:d.nx]...)

    b = b[:len(b) + len(d.x) - int(d.nx)]
    b = appendUint64(b, d.len)

    b = appendUint32(b, d.h[0])
    b = appendUint32(b, d.h[1])
    b = appendUint32(b, d.h[2])
    b = appendUint32(b, d.h[3])
    b = appendUint32(b, d.h[4])
    b = appendUint32(b, d.h[5])
    b = appendUint32(b, d.h[6])
    b = appendUint32(b, d.h[7])

    b = appendUint64(b, d.t)

    if d.nullt {
        b = append(b, byte(1))
    } else {
        b = append(b, byte(0))
    }

    return b, nil
}

func (d *digest) UnmarshalBinary(b []byte) error {
    if len(b) < len(magic) || (string(b[:len(magic)]) != magic) {
        return errors.New("go-hash/blake256: invalid hash state identifier")
    }

    if len(b) != marshaledSize {
        return errors.New("go-hash/blake256: invalid hash state size")
    }

    b = b[len(magic):]

    b, d.s[0] = consumeUint32(b)
    b, d.s[1] = consumeUint32(b)
    b, d.s[2] = consumeUint32(b)
    b, d.s[3] = consumeUint32(b)

    b = b[copy(d.x[:], b):]

    var length uint64
    b, length = consumeUint64(b)

    d.nx = int(length % chunk)
    d.len = length

    b, d.h[0] = consumeUint32(b)
    b, d.h[1] = consumeUint32(b)
    b, d.h[2] = consumeUint32(b)
    b, d.h[3] = consumeUint32(b)
    b, d.h[4] = consumeUint32(b)
    b, d.h[5] = consumeUint32(b)
    b, d.h[6] = consumeUint32(b)
    b, d.h[7] = consumeUint32(b)

    b, d.t = consumeUint64(b)

    if b[0] == 1 {
        d.nullt = true
    } else {
        d.nullt = false
    }

    return nil
}

func appendUint64(b []byte, x uint64) []byte {
    var a [8]byte
    binary.BigEndian.PutUint64(a[:], x)
    return append(b, a[:]...)
}

func appendUint32(b []byte, x uint32) []byte {
    var a [4]byte
    binary.BigEndian.PutUint32(a[:], x)
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

func consumeUint32(b []byte) ([]byte, uint32) {
    _ = b[3]

    x := uint32(b[3])       |
         uint32(b[2]) <<  8 |
         uint32(b[1]) << 16 |
         uint32(b[0]) << 24

    return b[4:], x
}
