package cubehash

import (
    "hash"
    "errors"
)

// The size of an cubehash checksum in bytes.
const Size = 64

// The blocksize of cubehash in bytes.
const BlockSize = 32

var invalidErr = errors.New("invalid CubeHash state")

type digest struct {
    s   [32]uint32
    x   [BlockSize]byte
    nx  int
    len uint64
}

// New returns a new hash.Hash for CubeHash16+16/32+32–512.
func New() hash.Hash {
    var d digest
    d.Reset()
    return &d
}

func (this *digest) Reset() {
    x := &this.s

    x[0] = Size
    x[1] = BlockSize
    x[2] = 16 // the number of rounds per message block
    for n := 3; n < 32; n++ {
        x[n] = 0
    }

    // the number of initialization rounds
    for n := 0; n < 16; n++ {
        round(x)
    }

    this.x = [BlockSize]byte{}

    this.nx = 0
    this.len = 0
}

func (this *digest) Size() int {
    return Size
}

func (this *digest) BlockSize() int {
    return BlockSize
}

func (this *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    plen := len(p)

    var limit = BlockSize
    for this.nx + plen >= limit {
        xx := limit - this.nx

        copy(this.x[this.nx:], p)

        ingest(&this.s, this.x[:])

        plen -= xx

        p = p[xx:]
        this.nx = 0
    }

    copy(this.x[this.nx:], p)
    this.nx += plen

    return
}

func (this *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *this
    hash := d0.checkSum()
    return append(in, hash[:]...)
}

func (this *digest) checkSum() [Size]byte {
    x := this.s

    var pad [BlockSize]byte
    copy(pad[:], this.x[:this.nx])
    pad[this.nx] = 0x80
    ingest(&x, pad[:])

    // the number of finalization rounds
    x[31] ^= 1
    for n := 0; n < 32; n++ {
        round(&x)
    }

    var buf [Size]byte
    for n := 0; n < Size/4; n++ {
        PUTU32(buf[n*4:], x[n])
    }

    return buf
}

func (this *digest) MarshalBinary() ([]byte, error) {
    x := &this.s
    buf := make([]byte, 128+1, 128+1+this.nx)
    for n := 0; n < 32; n++ {
        PUTU32(buf[n*4:], x[n])
    }

    buf[128] = byte(this.nx)
    return append(buf, this.x[:this.nx]...), nil
}

func (this *digest) UnmarshalBinary(data []byte) error {
    x := &this.s
    if len(data) < 128+1 {
        return invalidErr
    }

    n := int(data[128])
    if n >= BlockSize || len(data) < 128+1+n {
        return invalidErr
    }
    this.nx = n

    for n := 0; n < 32; n++ {
        x[n] = GETU32(data[n*4:])
    }

    this.len = 0

    copy(this.x[:n], data[129:])
    return nil
}
