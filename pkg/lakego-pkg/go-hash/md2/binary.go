package md2

import (
    "errors"
    "encoding/binary"
)

const (
    chunk         = 16
    magic         = "md2\x03"
    marshaledSize = len(magic) + 48 + chunk + 8 + 16
)

func (this *digest) MarshalBinary() ([]byte, error) {
    b := make([]byte, 0, marshaledSize)
    b = append(b, magic...)

    b = append(b, this.s[:]...)

    x := make([]byte, chunk)
    copy(x, this.x[:this.nx])
    b = append(b, x...)

    b = appendUint64(b, this.len)

    b = append(b, this.digest[:]...)

    return b, nil
}

func (this *digest) UnmarshalBinary(b []byte) error {
    if len(b) < len(magic) || (string(b[:len(magic)]) != magic) {
        return errors.New("go-hash/md2: invalid hash state identifier")
    }

    if len(b) != marshaledSize {
        return errors.New("go-hash/md2: invalid hash state size")
    }

    b = b[len(magic):]

    b = b[copy(this.s[:], b):]
    b = b[copy(this.x[:], b):]

    var length uint64
    b, length = consumeUint64(b)

    this.nx = int(length % chunk)
    this.len = length

    b = b[copy(this.digest[:], b):]

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
