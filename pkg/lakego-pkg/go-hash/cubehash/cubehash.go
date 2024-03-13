// Package cubehash implement's djb's CubeHash cryptographic hash
// function. The hash.Hash implementation returned by this package also
// implements encoding.BinaryMarshaler and encoding.BinaryUnmarshaler.
package cubehash

import (
    "hash"
    "errors"
    "encoding"
    "math/bits"
    "encoding/binary"
)

const (
    // in {1,2,3,...}, the number of initialization rounds
    i = 16
    // in {1,2,3,...}, the number of rounds per message block
    r = 16
    // in {1,2,3,...,128}, the number of bytes per message block
    b = 32
    // in {1,2,3,...}, the number of finalization rounds
    f = 32
    // in {8,16,24,...,512}, the number of output bits
    h = 512
)

// The size of an cubehash checksum in bytes.
const Size = h / 8

// The blocksize of cubehash in bytes.
const BlockSize = b

var invalidErr = errors.New("invalid CubeHash state")

type cubehash struct {
    s   [32]uint32
    buf [b]byte
    n   int
}

// New returns a new hash.Hash for CubeHash16+16/32+32–512.
func New() hash.Hash {
    var c cubehash
    c.Reset()
    return &c
}

var _ hash.Hash = (*cubehash)(nil)
var _ encoding.BinaryMarshaler = (*cubehash)(nil)
var _ encoding.BinaryUnmarshaler = (*cubehash)(nil)

func (c *cubehash) Reset() {
    x := &c.s

    x[0] = h / 8
    x[1] = b
    x[2] = r
    for n := 3; n < 32; n++ {
        x[n] = 0
    }
    for n := 0; n < i; n++ {
        round(x)
    }

    // Sanitize the buffer while we're at it
    c.n = 0
    for n := 0; n < b; n++ {
        c.buf[n] = 0
    }
}

func (c *cubehash) Size() int {
    return Size
}

func (c *cubehash) BlockSize() int {
    return BlockSize
}

func (c *cubehash) Write(p []byte) (total int, err error) {
    x := &c.s
    total = len(p)

    if c.n > 0 {
        amt := copy(c.buf[c.n:], p[:])
        c.n += amt
        p = p[amt:]
        if c.n == b {
            c.n = 0
            ingest(x, c.buf[:])
        } else {
            return
        }
    }

    for len(p) >= b {
        ingest(x, p[:b])
        p = p[b:]
    }
    c.n = copy(c.buf[:], p[:])

    return
}

func (c *cubehash) Sum(p []byte) []byte {
    x := c.s // copy internal state!

    var pad [b]byte
    copy(pad[:], c.buf[:c.n])
    pad[c.n] = 0x80
    ingest(&x, pad[:])

    x[31] ^= 1
    for n := 0; n < f; n++ {
        round(&x)
    }

    var buf [h / 8]byte
    for n := 0; n < h/8/4; n++ {
        binary.LittleEndian.PutUint32(buf[n*4:], x[n])
    }
    return append(p, buf[:]...)
}

func (c *cubehash) MarshalBinary() ([]byte, error) {
    x := &c.s
    buf := make([]byte, 128+1, 128+1+c.n)
    for n := 0; n < 32; n++ {
        binary.LittleEndian.PutUint32(buf[n*4:], x[n])
    }
    buf[128] = byte(c.n)
    return append(buf, c.buf[:c.n]...), nil
}

func (c *cubehash) UnmarshalBinary(data []byte) error {
    x := &c.s
    if len(data) < 128+1 {
        return invalidErr
    }

    n := int(data[128])
    if n >= b || len(data) < 128+1+n {
        return invalidErr
    }
    c.n = n

    for n := 0; n < 32; n++ {
        x[n] = binary.LittleEndian.Uint32(data[n*4:])
    }
    copy(c.buf[:n], data[129:])
    return nil
}

func ingest(x *[32]uint32, p []byte) {
    for n := 0; n < b/4; n++ {
        x[n] ^= binary.LittleEndian.Uint32(p[n*4:])
    }
    for n := 0; n < r; n++ {
        round(x)
    }
}

func round(x *[32]uint32) {
    for n := 0; n < 16; n++ {
        x[n+16] += x[n]
        x[n] = bits.RotateLeft32(x[n], 7)
    }
    x[0], x[8] = x[8], x[0]
    x[1], x[9] = x[9], x[1]
    x[2], x[10] = x[10], x[2]
    x[3], x[11] = x[11], x[3]
    x[4], x[12] = x[12], x[4]
    x[5], x[13] = x[13], x[5]
    x[6], x[14] = x[14], x[6]
    x[7], x[15] = x[15], x[7]
    for n := 0; n < 16; n++ {
        x[n] ^= x[n+16]
    }
    x[16], x[18] = x[18], x[16]
    x[17], x[19] = x[19], x[17]
    x[20], x[22] = x[22], x[20]
    x[21], x[23] = x[23], x[21]
    x[24], x[26] = x[26], x[24]
    x[25], x[27] = x[27], x[25]
    x[28], x[30] = x[30], x[28]
    x[29], x[31] = x[31], x[29]
    for n := 0; n < 16; n++ {
        x[n+16] += x[n]
        x[n] = bits.RotateLeft32(x[n], 11)
    }
    x[0], x[4] = x[4], x[0]
    x[1], x[5] = x[5], x[1]
    x[2], x[6] = x[6], x[2]
    x[3], x[7] = x[7], x[3]
    x[8], x[12] = x[12], x[8]
    x[9], x[13] = x[13], x[9]
    x[10], x[14] = x[14], x[10]
    x[11], x[15] = x[15], x[11]
    for n := 0; n < 16; n++ {
        x[n] ^= x[n+16]
    }
    x[16], x[17] = x[17], x[16]
    x[18], x[19] = x[19], x[18]
    x[20], x[21] = x[21], x[20]
    x[22], x[23] = x[23], x[22]
    x[24], x[25] = x[25], x[24]
    x[26], x[27] = x[27], x[26]
    x[28], x[29] = x[29], x[28]
    x[30], x[31] = x[31], x[30]
}
