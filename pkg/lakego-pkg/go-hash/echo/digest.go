package echo

import (
    "hash"
    "errors"
)

const (
    // hash size
    Size224 = 28
    Size256 = 32
    Size384 = 48
    Size512 = 64
)

// digest represents the partial evaluation of a checksum.
type digest struct {
    s   [32]uint64
    x   []byte
    nx  int
    len uint64

    hs, bs int
    salt [2]uint64
}

// New returns a new hash.Hash computing the echo checksum
func New(hs int) (hash.Hash, error) {
    return NewWithSalt(hs, nil)
}

// New returns a new hash.Hash computing the echo checksum
func NewWithSalt(hashsize int, salt []byte) (hash.Hash, error) {
    if hashsize == 0 {
        return nil, errors.New("go-hash/echo: hash size can't be zero")
    }
    if (hashsize % 8) > 0 {
        return nil, errors.New("go-hash/echo: non-byte hash sizes are not supported")
    }
    if hashsize > 512 {
        return nil, errors.New("go-hash/echo: invalid hash size")
    }

    d := new(digest)
    d.hs = hashsize

    if len(salt) > 0 {
        if len(salt) != 16 {
            return nil, errors.New("go-hash/echo: invalid salt length")
        }

        s := bytesToUint64s(salt)
        copy(d.salt[:], s)
    } else {
        d.salt = [2]uint64{}
    }

    d.Reset()

    return d, nil
}

func (d *digest) Reset() {
    if d.hs > 256 {
        d.bs = 1024
    } else {
        d.bs = 1536
    }

    // m
    d.x = make([]byte, d.bs / 8)

    // h
    d.s = [32]uint64{}

    var r int
    if d.hs > 256 {
        r = 8
    } else {
        r = 4
    }

    var i int
    for i = 0; i < r; i++ {
        d.s[2 * i] = uint64(d.hs)
        d.s[2 * i + 1] = 0
    }

    d.nx = 0
    d.len = 0
}

func (d *digest) Size() int {
    return d.hs / 8
}

func (d *digest) BlockSize() int {
    return d.bs / 8
}

func (d *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    plen := len(p)

    var limit = d.bs / 8
    for d.nx + plen >= limit {
        xx := limit - d.nx

        copy(d.x[d.nx:], p)

        d.transform(true, uint64(xx) * 8)

        plen -= xx
        d.len += uint64(xx) * 8

        p = p[xx:]
        d.nx = 0
    }

    copy(d.x[d.nx:], p)
    d.nx += plen
    d.len += uint64(plen) * 8

    return
}

func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *digest) checkSum() []byte {
    d.x[d.nx] = 0x80
    d.nx++

    var limit = d.bs / 8

    zeros := make([]byte, limit)

    if d.nx > limit - 18 {
        copy(d.x[d.nx:], zeros)
        d.transform(true, 0)
        d.nx = 0
    }

    copy(d.x[d.nx:], zeros)

    var hsize = uint16(d.hs)

    PUTU16(d.x[limit - 18:], hsize)
    PUTU64(d.x[limit - 16:], d.len)
    copy(d.x[limit - 8:], zeros)

    if d.nx > 1 {
        d.transform(true, 0)
    } else {
        d.transform(false, 0)
    }

    ss := uint64sToBytes(d.s[:])
    return ss[:d.hs / 8]
}

func (d *digest) transform(addedbits bool, addtototal uint64) {
    var counter uint64 = 0
    if addedbits {
        counter = d.len + addtototal
    }

    xx := bytesToUint64s(d.x)
    copy(d.s[32-len(xx):], xx)

    var w [32]uint64
    copy(w[:], d.s[:])

    var rounds int
    if d.hs > 256 {
        rounds = 10
    } else {
        rounds = 8
    }

    var l, r, i, j int
    for l = 0; l < rounds; l++ {
        for r = 0; r < 16; r++ {
            var idx int = r * 2
            var idx1 int = r * 2 + 1

            var t0 uint32 = uint32(counter) ^
                T[0][byte(w[idx])] ^
                T[1][byte(w[idx] >> 40)] ^
                T[2][byte(w[idx1] >> 16)] ^
                T[3][byte(w[idx1] >> 56)]
            var t1 uint32 = uint32(counter >> 32) ^
                T[0][byte(w[idx] >> 32)] ^
                T[1][byte(w[idx1] >> 8)] ^
                T[2][byte(w[idx1] >> 48)] ^
                T[3][byte(w[idx] >> 24)]
            var t2 uint32 = T[0][byte(w[idx1])] ^
                T[1][byte(w[idx1] >> 40)] ^
                T[2][byte(w[idx] >> 16)] ^
                T[3][byte(w[idx] >> 56)]
            var t3 uint32 = T[0][byte(w[idx1] >> 32)] ^
                T[1][byte(w[idx] >> 8)] ^
                T[2][byte(w[idx] >> 48)] ^
                T[3][byte(w[idx1] >> 24)]

            counter++

            w[idx] = uint64(T[0][byte(t0)] ^
                T[1][byte(t1 >> 8)] ^
                T[2][byte(t2 >> 16)] ^
                T[3][byte(t3 >> 24)]) ^
                (uint64(T[0][byte(t1)] ^
                        T[1][byte(t2 >> 8)] ^
                        T[2][byte(t3 >> 16)] ^
                        T[3][byte(t0 >> 24)]) << 32) ^
                d.salt[0]
            w[idx + 1] = uint64(T[0][byte(t2)] ^
                T[1][byte(t3 >> 8)] ^
                T[2][byte(t0 >> 16)] ^
                T[3][byte(t1 >> 24)]) ^
                (uint64(T[0][byte(t3)] ^
                        T[1][byte(t0 >> 8)] ^
                        T[2][byte(t1 >> 16)] ^
                        T[3][byte(t2 >> 24)]) << 32) ^
                d.salt[1]
        }

        w[2], w[10] = w[10], w[2]
        w[3], w[11] = w[11], w[3]
        w[4], w[20] = w[20], w[4]
        w[5], w[21] = w[21], w[5]
        w[6], w[30] = w[30], w[6]
        w[7], w[31] = w[31], w[7]
        w[12], w[28] = w[28], w[12]
        w[13], w[29] = w[29], w[13]
        w[22], w[14] = w[14], w[22]
        w[23], w[15] = w[15], w[23]
        w[30], w[14] = w[14], w[30]
        w[31], w[15] = w[15], w[31]
        w[26], w[18] = w[18], w[26]
        w[27], w[19] = w[19], w[27]
        w[26], w[10] = w[10], w[26]
        w[27], w[11] = w[11], w[27]

        for i = 0; i < 4; i++ {
            for j = 0; j < 2; j++ {
                var idx int = i * 4 * 2 + j
                var a uint64 = w[idx]
                var b uint64 = w[idx + 2]
                var c uint64 = w[idx + 4]
                var d uint64 = w[idx + 6]

                var dblA uint64 = ((a << 1) & firstbits) ^ (((a >> 7) & lastbit) * 0x1b)
                var dblB uint64 = ((b << 1) & firstbits) ^ (((b >> 7) & lastbit) * 0x1b)
                var dblC uint64 = ((c << 1) & firstbits) ^ (((c >> 7) & lastbit) * 0x1b)
                var dblD uint64 = ((d << 1) & firstbits) ^ (((d >> 7) & lastbit) * 0x1b)

                w[idx] = dblA ^ dblB ^ b ^ c ^ d
                w[idx + 2] = dblB ^ dblC ^ c ^ d ^ a
                w[idx + 4] = dblC ^ dblD ^ d ^ a ^ b
                w[idx + 6] = dblD ^ dblA ^ a ^ b ^ c
            }
        }
    }

    h := &d.s

    if d.hs <= 256 {
        for i = 0; i < 8; i++ {
            h[i] = h[i] ^ h[i+8] ^ h[i+16] ^ h[i+24] ^ w[i] ^ w[i+8] ^ w[i+16] ^ w[i+24]
        }
    } else {
        for i = 0; i < 16; i++ {
            h[i] = h[i] ^ h[i+16] ^ w[i] ^ w[i+16]
        }
    }
}
