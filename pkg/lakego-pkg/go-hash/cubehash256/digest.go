package cubehash256

import (
    "hash"
    "errors"
)

// The size of an cubehash checksum in bytes.
const Size256 = 32

// The blocksize of cubehash in bytes.
const BlockSize = 32

var invalidErr = errors.New("invalid CubeHash state")

var iv256 = []uint32{
    0xEA2BD4B4, 0xCCD6F29F, 0x63117E71,
    0x35481EAE, 0x22512D5B, 0xE5D94E63,
    0x7E624131, 0xF4CC12BE, 0xC2D0B696,
    0x42AF2070, 0xD0720C35, 0x3361DA8C,
    0x28CCECA4, 0x8EF8AD83, 0x4680AC00,
    0x40E5FBAB, 0xD89041C3, 0x6107FBD5,
    0x6C859D41, 0xF0B26679, 0x09392549,
    0x5FA25603, 0x65C892FD, 0x93CB6285,
    0x2AF2B5AE, 0x9E4B4E60, 0x774ABFDD,
    0x85254725, 0x15815AEB, 0x4AB6AAD6,
    0x9CDAF8AF, 0xD6032C0A,
}

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
    this.s = [32]uint32{}
    this.x = [BlockSize]byte{}

    this.nx = 0
    this.len = 0

    copy(this.s[:], iv256)
}

func (this *digest) Size() int {
    return Size256
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

        this.compress(&this.s, this.x[:])

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

func (this *digest) checkSum() (out [Size256]byte) {
    this.x[this.nx] = 0x80
    this.nx++

    var limit = BlockSize
    zeros := make([]byte, limit)

    copy(this.x[this.nx:], zeros)
    this.compress(&this.s, this.x[:])

    this.s[31] ^= 1
    for j := 0; j < 80; j++ {
        this.round(&this.s)
    }

    ss := uint32sToBytes(this.s[:8])
    copy(out[:], ss)

    return
}

func (this *digest) compress(x *[32]uint32, p []byte) {
    for n := 0; n < BlockSize/4; n++ {
        this.s[n] ^= GETU32(p[n*4:])
    }

    for i := 0; i < 8; i++ {
        this.round(x)
    }
}

func (this *digest) round(x *[32]uint32) {
    var n int
    for n = 0; n < 16; n++ {
        x[n+16] += x[n]
        x[n] = rotl(x[n], 7)
    }

    for n = 8; n < 16; n++ {
        x[n] ^= x[n+8]
    }
    for n = 0; n < 8; n++ {
        x[n] ^= x[n+24]
    }

    x[18] = x[8] + x[18]
    x[19] = x[9] + x[19]
    x[16] = x[10] + x[16]
    x[17] = x[11] + x[17]
    x[22] = x[12] + x[22]
    x[23] = x[13] + x[23]
    x[20] = x[14] + x[20]
    x[21] = x[15] + x[21]
    for n = 8; n < 16; n++ {
        x[n] = rotl(x[n], 11)
    }

    x[26] = x[0] + x[26]
    x[27] = x[1] + x[27]
    x[24] = x[2] + x[24]
    x[25] = x[3] + x[25]
    x[30] = x[4] + x[30]
    x[31] = x[5] + x[31]
    x[28] = x[6] + x[28]
    x[29] = x[7] + x[29]
    for n = 0; n < 8; n++ {
        x[n] = rotl(x[n], 11)
    }

    for n = 0; n < 16; n += 4 {
        x[n+0] ^= x[30-n]
        x[n+1] ^= x[31-n]
        x[n+2] ^= x[28-n]
        x[n+3] ^= x[29-n]
    }

    x[19] = x[12] + x[19]
    x[18] = x[13] + x[18]
    x[17] = x[14] + x[17]
    x[16] = x[15] + x[16]
    x[23] = x[8] + x[23]
    x[22] = x[9] + x[22]
    x[21] = x[10] + x[21]
    x[20] = x[11] + x[20]
    for n = 8; n < 16; n++ {
        x[n] = rotl(x[n], 7)
    }

    x[27] = x[4] + x[27]
    x[26] = x[5] + x[26]
    x[25] = x[6] + x[25]
    x[24] = x[7] + x[24]
    x[31] = x[0] + x[31]
    x[30] = x[1] + x[30]
    x[29] = x[2] + x[29]
    x[28] = x[3] + x[28]
    for n = 0; n < 8; n++ {
        x[n] = rotl(x[n], 7)
    }

    x[4] ^= x[19]
    x[5] ^= x[18]
    x[6] ^= x[17]
    x[7] ^= x[16]
    x[0] ^= x[23]
    x[1] ^= x[22]
    x[2] ^= x[21]
    x[3] ^= x[20]
    x[12] ^= x[27]
    x[13] ^= x[26]
    x[14] ^= x[25]
    x[15] ^= x[24]
    x[8] ^= x[31]
    x[9] ^= x[30]
    x[10] ^= x[29]
    x[11] ^= x[28]

    x[17] = x[4] + x[17]
    x[16] = x[5] + x[16]
    x[19] = x[6] + x[19]
    x[18] = x[7] + x[18]
    x[21] = x[0] + x[21]
    x[20] = x[1] + x[20]
    x[23] = x[2] + x[23]
    x[22] = x[3] + x[22]
    for n = 0; n < 8; n++ {
        x[n] = rotl(x[n], 11)
    }

    x[25] = x[12] + x[25]
    x[24] = x[13] + x[24]
    x[27] = x[14] + x[27]
    x[26] = x[15] + x[26]
    x[29] = x[8] + x[29]
    x[28] = x[9] + x[28]
    x[31] = x[10] + x[31]
    x[30] = x[11] + x[30]
    for n = 8; n < 16; n++ {
        x[n] = rotl(x[n], 11)
    }

    for n = 0; n < 15; n += 2 {
        x[n+0] ^= x[n+17]
        x[n+1] ^= x[n+16]
    }
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
