package cubehash

import (
    "errors"
)

const (
    // The size of an cubehash checksum in bytes.
    Size512 = 64
    Size384 = 48
    Size256 = 32
    Size224 = 28
    Size192 = 24
    Size160 = 20
    Size128 = 16
)

// The blocksize of cubehash in bytes.
const BlockSize = 32

var errInvalid = errors.New("invalid CubeHash state")

type digest struct {
    s   [32]uint32
    x   []byte
    nx  int
    len uint64

    hs int
    bs int
    r  int // the number of rounds per message block
    ir int // the number of initialization rounds
    fr int // the number of finalization rounds
}

// newDigest returns a new hash.Hash.
func newDigest(hashSize, blockSize, r, ir, fr int) *digest {
    d := new(digest)

    d.hs = hashSize
    d.bs = blockSize
    d.r = r
    d.ir = ir
    d.fr = fr

    d.Reset()
    return d
}

func (this *digest) Reset() {
    this.initRound(this.ir)

    this.x = make([]byte, this.bs)

    this.nx = 0
    this.len = 0
}

func (this *digest) Size() int {
    return this.hs / 8
}

func (this *digest) BlockSize() int {
    return this.bs
}

func (this *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    plen := len(p)

    var limit = this.bs
    for this.nx + plen >= limit {
        xx := limit - this.nx

        copy(this.x[this.nx:], p)

        this.ingest(&this.s, this.x[:])

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
    d0 := this.copy()
    hash := d0.checkSum()
    return append(in, hash[:]...)
}

func (this *digest) checkSum() []byte {
    x := this.s

    var pad = make([]byte, this.bs)
    copy(pad[:], this.x[:this.nx])

    pad[this.nx] = 0x80
    this.ingest(&x, pad[:])

    // the number of finalization rounds
    x[31] ^= 1
    for n := 0; n < this.fr; n++ {
        round(&x)
    }

    buf := uint32sToBytes(x[:this.hs/32])
    return buf
}

func (this *digest) initRound(r int) {
    x := &this.s

    x[0] = uint32(this.hs / 8)
    x[1] = uint32(this.bs)
    x[2] = uint32(this.r) // the number of rounds per message block
    for n := 3; n < 32; n++ {
        x[n] = 0
    }

    // the number of initialization rounds
    for n := 0; n < r; n++ {
        round(x)
    }
}

func (this *digest) ingest(x *[32]uint32, p []byte) {
    for n := 0; n < this.bs/4; n++ {
        x[n] ^= getu32(p[n*4:])
    }

    // the number of rounds per message block
    for n := 0; n < this.r; n++ {
        round(x)
    }
}

func (this *digest) copy() *digest {
    d0 := &digest{}

    d0.s = this.s

    d0.x = make([]byte, len(this.x))
    copy(d0.x, this.x)

    d0.nx = this.nx
    d0.len = this.len

    d0.hs = this.hs
    d0.bs = this.bs
    d0.r = this.r
    d0.ir = this.ir
    d0.fr = this.fr

    return d0
}

func (this *digest) MarshalBinary() ([]byte, error) {
    x := &this.s
    buf := make([]byte, 128+1, 128+1+this.nx)
    for n := 0; n < 32; n++ {
        putu32(buf[n*4:], x[n])
    }

    buf[128] = byte(this.nx)
    return append(buf, this.x[:this.nx]...), nil
}

func (this *digest) UnmarshalBinary(data []byte) error {
    x := &this.s
    if len(data) < 128+1 {
        return errInvalid
    }

    n := int(data[128])
    if n >= this.bs || len(data) < 128+1+n {
        return errInvalid
    }
    this.nx = n

    for n := 0; n < 32; n++ {
        x[n] = getu32(data[n*4:])
    }

    this.len = 0

    copy(this.x[:n], data[129:])
    return nil
}
