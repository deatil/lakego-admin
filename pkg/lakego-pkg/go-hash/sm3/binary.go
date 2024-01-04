package sm3

import (
    "errors"
    "encoding/binary"
)

const (
    chunk         = 64
    magic256      = "sm3\x03"
    marshaledSize = len(magic256) + 8*4 + chunk + 8
)

func (d *digest) MarshalBinary() ([]byte, error) {
    b := make([]byte, 0, marshaledSize)
    b = append(b, magic256...)

    b = appendUint32(b, d.digest[0])
    b = appendUint32(b, d.digest[1])
    b = appendUint32(b, d.digest[2])
    b = appendUint32(b, d.digest[3])
    b = appendUint32(b, d.digest[4])
    b = appendUint32(b, d.digest[5])
    b = appendUint32(b, d.digest[6])
    b = appendUint32(b, d.digest[7])

    b = append(b, d.block[:d.num]...)

    length := (d.nblocks * BlockSize) + uint64(d.num)

    b = b[:len(b) + len(d.block) - int(d.num)]
    b = appendUint64(b, length)

    return b, nil
}

func (d *digest) UnmarshalBinary(b []byte) error {
    if len(b) < len(magic256) || (string(b[:len(magic256)]) != magic256) {
        return errors.New("sm3: invalid hash state identifier")
    }

    if len(b) != marshaledSize {
        return errors.New("sm3: invalid hash state size")
    }

    b = b[len(magic256):]

    b, d.digest[0] = consumeUint32(b)
    b, d.digest[1] = consumeUint32(b)
    b, d.digest[2] = consumeUint32(b)
    b, d.digest[3] = consumeUint32(b)
    b, d.digest[4] = consumeUint32(b)
    b, d.digest[5] = consumeUint32(b)
    b, d.digest[6] = consumeUint32(b)
    b, d.digest[7] = consumeUint32(b)

    b = b[copy(d.block[:], b):]

    var length uint64

    b, length = consumeUint64(b)

    d.num = int(length % chunk)
    d.nblocks = length / chunk

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
