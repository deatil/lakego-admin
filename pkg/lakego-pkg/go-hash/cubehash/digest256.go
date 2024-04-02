package cubehash

import (
    "hash"
)

// The size of an cubehash checksum in bytes.
const Size256 = 32

// The blocksize of cubehash in bytes.
const BlockSize256 = 32

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

type digest256 struct {
    s   [32]uint32
    x   [BlockSize]byte
    nx  int
    len uint64
}

// New256 returns a new hash.Hash for CubeHash16+16/32+32–512.
func New256() hash.Hash {
    var d digest256
    d.Reset()
    return &d
}

func (this *digest256) Reset() {
    this.s = [32]uint32{}
    this.x = [BlockSize]byte{}

    this.nx = 0
    this.len = 0

    copy(this.s[:], iv256)
}

func (this *digest256) Size() int {
    return Size256
}

func (this *digest256) BlockSize() int {
    return BlockSize256
}

func (this *digest256) Write(p []byte) (nn int, err error) {
    nn = len(p)

    plen := len(p)

    var limit = BlockSize
    for this.nx + plen >= limit {
        xx := limit - this.nx

        copy(this.x[this.nx:], p)

        this.inputBlock(this.x[:])
        this.sixteenRounds()

        plen -= xx

        p = p[xx:]
        this.nx = 0
    }

    copy(this.x[this.nx:], p)
    this.nx += plen

    return
}

func (this *digest256) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *this
    hash := d0.checkSum()
    return append(in, hash[:]...)
}

func (this *digest256) checkSum() (out [Size256]byte) {
    this.x[this.nx] = 0x80
    this.nx++

    var limit = BlockSize
    zeros := make([]byte, limit)

    copy(this.x[this.nx:], zeros)
    this.inputBlock(this.x[:])
    this.sixteenRounds()

    this.s[31] ^= 1
    for j := 0; j < 10; j++ {
        this.sixteenRounds()
    }

    ss := uint32sToBytes(this.s[:8])
    copy(out[:], ss)

    return
}

func (this *digest256) inputBlock(data []byte) {
    this.s[0] ^= GETU32(data[0:])
    this.s[1] ^= GETU32(data[4:])
    this.s[2] ^= GETU32(data[8:])
    this.s[3] ^= GETU32(data[12:])
    this.s[4] ^= GETU32(data[16:])
    this.s[5] ^= GETU32(data[20:])
    this.s[6] ^= GETU32(data[24:])
    this.s[7] ^= GETU32(data[28:])
}

func (this *digest256) sixteenRounds() {
    for i := 0; i < 8; i++ {
        this.s[16] = this.s[0] + this.s[16]
        this.s[0] = (this.s[0] << 7) | (this.s[0] >> (32 - 7))
        this.s[17] = this.s[1] + this.s[17]
        this.s[1] = (this.s[1] << 7) | (this.s[1] >> (32 - 7))
        this.s[18] = this.s[2] + this.s[18]
        this.s[2] = (this.s[2] << 7) | (this.s[2] >> (32 - 7))
        this.s[19] = this.s[3] + this.s[19]
        this.s[3] = (this.s[3] << 7) | (this.s[3] >> (32 - 7))
        this.s[20] = this.s[4] + this.s[20]
        this.s[4] = (this.s[4] << 7) | (this.s[4] >> (32 - 7))
        this.s[21] = this.s[5] + this.s[21]
        this.s[5] = (this.s[5] << 7) | (this.s[5] >> (32 - 7))
        this.s[22] = this.s[6] + this.s[22]
        this.s[6] = (this.s[6] << 7) | (this.s[6] >> (32 - 7))
        this.s[23] = this.s[7] + this.s[23]
        this.s[7] = (this.s[7] << 7) | (this.s[7] >> (32 - 7))
        this.s[24] = this.s[8] + this.s[24]
        this.s[8] = (this.s[8] << 7) | (this.s[8] >> (32 - 7))
        this.s[25] = this.s[9] + this.s[25]
        this.s[9] = (this.s[9] << 7) | (this.s[9] >> (32 - 7))
        this.s[26] = this.s[10] + this.s[26]
        this.s[10] = (this.s[10] << 7) | (this.s[10] >> (32 - 7))
        this.s[27] = this.s[11] + this.s[27]
        this.s[11] = (this.s[11] << 7) | (this.s[11] >> (32 - 7))
        this.s[28] = this.s[12] + this.s[28]
        this.s[12] = (this.s[12] << 7) | (this.s[12] >> (32 - 7))
        this.s[29] = this.s[13] + this.s[29]
        this.s[13] = (this.s[13] << 7) | (this.s[13] >> (32 - 7))
        this.s[30] = this.s[14] + this.s[30]
        this.s[14] = (this.s[14] << 7) | (this.s[14] >> (32 - 7))
        this.s[31] = this.s[15] + this.s[31]
        this.s[15] = (this.s[15] << 7) | (this.s[15] >> (32 - 7))
        this.s[8] ^= this.s[16]
        this.s[9] ^= this.s[17]
        this.s[10] ^= this.s[18]
        this.s[11] ^= this.s[19]
        this.s[12] ^= this.s[20]
        this.s[13] ^= this.s[21]
        this.s[14] ^= this.s[22]
        this.s[15] ^= this.s[23]
        this.s[0] ^= this.s[24]
        this.s[1] ^= this.s[25]
        this.s[2] ^= this.s[26]
        this.s[3] ^= this.s[27]
        this.s[4] ^= this.s[28]
        this.s[5] ^= this.s[29]
        this.s[6] ^= this.s[30]
        this.s[7] ^= this.s[31]
        this.s[18] = this.s[8] + this.s[18]
        this.s[8] = (this.s[8] << 11) | (this.s[8] >> (32 - 11))
        this.s[19] = this.s[9] + this.s[19]
        this.s[9] = (this.s[9] << 11) | (this.s[9] >> (32 - 11))
        this.s[16] = this.s[10] + this.s[16]
        this.s[10] = (this.s[10] << 11) | (this.s[10] >> (32 - 11))
        this.s[17] = this.s[11] + this.s[17]
        this.s[11] = (this.s[11] << 11) | (this.s[11] >> (32 - 11))
        this.s[22] = this.s[12] + this.s[22]
        this.s[12] = (this.s[12] << 11) | (this.s[12] >> (32 - 11))
        this.s[23] = this.s[13] + this.s[23]
        this.s[13] = (this.s[13] << 11) | (this.s[13] >> (32 - 11))
        this.s[20] = this.s[14] + this.s[20]
        this.s[14] = (this.s[14] << 11) | (this.s[14] >> (32 - 11))
        this.s[21] = this.s[15] + this.s[21]
        this.s[15] = (this.s[15] << 11) | (this.s[15] >> (32 - 11))
        this.s[26] = this.s[0] + this.s[26]
        this.s[0] = (this.s[0] << 11) | (this.s[0] >> (32 - 11))
        this.s[27] = this.s[1] + this.s[27]
        this.s[1] = (this.s[1] << 11) | (this.s[1] >> (32 - 11))
        this.s[24] = this.s[2] + this.s[24]
        this.s[2] = (this.s[2] << 11) | (this.s[2] >> (32 - 11))
        this.s[25] = this.s[3] + this.s[25]
        this.s[3] = (this.s[3] << 11) | (this.s[3] >> (32 - 11))
        this.s[30] = this.s[4] + this.s[30]
        this.s[4] = (this.s[4] << 11) | (this.s[4] >> (32 - 11))
        this.s[31] = this.s[5] + this.s[31]
        this.s[5] = (this.s[5] << 11) | (this.s[5] >> (32 - 11))
        this.s[28] = this.s[6] + this.s[28]
        this.s[6] = (this.s[6] << 11) | (this.s[6] >> (32 - 11))
        this.s[29] = this.s[7] + this.s[29]
        this.s[7] = (this.s[7] << 11) | (this.s[7] >> (32 - 11))
        this.s[12] ^= this.s[18]
        this.s[13] ^= this.s[19]
        this.s[14] ^= this.s[16]
        this.s[15] ^= this.s[17]
        this.s[8] ^= this.s[22]
        this.s[9] ^= this.s[23]
        this.s[10] ^= this.s[20]
        this.s[11] ^= this.s[21]
        this.s[4] ^= this.s[26]
        this.s[5] ^= this.s[27]
        this.s[6] ^= this.s[24]
        this.s[7] ^= this.s[25]
        this.s[0] ^= this.s[30]
        this.s[1] ^= this.s[31]
        this.s[2] ^= this.s[28]
        this.s[3] ^= this.s[29]

        this.s[19] = this.s[12] + this.s[19]
        this.s[12] = (this.s[12] << 7) | (this.s[12] >> (32 - 7))
        this.s[18] = this.s[13] + this.s[18]
        this.s[13] = (this.s[13] << 7) | (this.s[13] >> (32 - 7))
        this.s[17] = this.s[14] + this.s[17]
        this.s[14] = (this.s[14] << 7) | (this.s[14] >> (32 - 7))
        this.s[16] = this.s[15] + this.s[16]
        this.s[15] = (this.s[15] << 7) | (this.s[15] >> (32 - 7))
        this.s[23] = this.s[8] + this.s[23]
        this.s[8] = (this.s[8] << 7) | (this.s[8] >> (32 - 7))
        this.s[22] = this.s[9] + this.s[22]
        this.s[9] = (this.s[9] << 7) | (this.s[9] >> (32 - 7))
        this.s[21] = this.s[10] + this.s[21]
        this.s[10] = (this.s[10] << 7) | (this.s[10] >> (32 - 7))
        this.s[20] = this.s[11] + this.s[20]
        this.s[11] = (this.s[11] << 7) | (this.s[11] >> (32 - 7))
        this.s[27] = this.s[4] + this.s[27]
        this.s[4] = (this.s[4] << 7) | (this.s[4] >> (32 - 7))
        this.s[26] = this.s[5] + this.s[26]
        this.s[5] = (this.s[5] << 7) | (this.s[5] >> (32 - 7))
        this.s[25] = this.s[6] + this.s[25]
        this.s[6] = (this.s[6] << 7) | (this.s[6] >> (32 - 7))
        this.s[24] = this.s[7] + this.s[24]
        this.s[7] = (this.s[7] << 7) | (this.s[7] >> (32 - 7))
        this.s[31] = this.s[0] + this.s[31]
        this.s[0] = (this.s[0] << 7) | (this.s[0] >> (32 - 7))
        this.s[30] = this.s[1] + this.s[30]
        this.s[1] = (this.s[1] << 7) | (this.s[1] >> (32 - 7))
        this.s[29] = this.s[2] + this.s[29]
        this.s[2] = (this.s[2] << 7) | (this.s[2] >> (32 - 7))
        this.s[28] = this.s[3] + this.s[28]
        this.s[3] = (this.s[3] << 7) | (this.s[3] >> (32 - 7))
        this.s[4] ^= this.s[19]
        this.s[5] ^= this.s[18]
        this.s[6] ^= this.s[17]
        this.s[7] ^= this.s[16]
        this.s[0] ^= this.s[23]
        this.s[1] ^= this.s[22]
        this.s[2] ^= this.s[21]
        this.s[3] ^= this.s[20]
        this.s[12] ^= this.s[27]
        this.s[13] ^= this.s[26]
        this.s[14] ^= this.s[25]
        this.s[15] ^= this.s[24]
        this.s[8] ^= this.s[31]
        this.s[9] ^= this.s[30]
        this.s[10] ^= this.s[29]
        this.s[11] ^= this.s[28]
        this.s[17] = this.s[4] + this.s[17]
        this.s[4] = (this.s[4] << 11) | (this.s[4] >> (32 - 11))
        this.s[16] = this.s[5] + this.s[16]
        this.s[5] = (this.s[5] << 11) | (this.s[5] >> (32 - 11))
        this.s[19] = this.s[6] + this.s[19]
        this.s[6] = (this.s[6] << 11) | (this.s[6] >> (32 - 11))
        this.s[18] = this.s[7] + this.s[18]
        this.s[7] = (this.s[7] << 11) | (this.s[7] >> (32 - 11))
        this.s[21] = this.s[0] + this.s[21]
        this.s[0] = (this.s[0] << 11) | (this.s[0] >> (32 - 11))
        this.s[20] = this.s[1] + this.s[20]
        this.s[1] = (this.s[1] << 11) | (this.s[1] >> (32 - 11))
        this.s[23] = this.s[2] + this.s[23]
        this.s[2] = (this.s[2] << 11) | (this.s[2] >> (32 - 11))
        this.s[22] = this.s[3] + this.s[22]
        this.s[3] = (this.s[3] << 11) | (this.s[3] >> (32 - 11))
        this.s[25] = this.s[12] + this.s[25]
        this.s[12] = (this.s[12] << 11) | (this.s[12] >> (32 - 11))
        this.s[24] = this.s[13] + this.s[24]
        this.s[13] = (this.s[13] << 11) | (this.s[13] >> (32 - 11))
        this.s[27] = this.s[14] + this.s[27]
        this.s[14] = (this.s[14] << 11) | (this.s[14] >> (32 - 11))
        this.s[26] = this.s[15] + this.s[26]
        this.s[15] = (this.s[15] << 11) | (this.s[15] >> (32 - 11))
        this.s[29] = this.s[8] + this.s[29]
        this.s[8] = (this.s[8] << 11) | (this.s[8] >> (32 - 11))
        this.s[28] = this.s[9] + this.s[28]
        this.s[9] = (this.s[9] << 11) | (this.s[9] >> (32 - 11))
        this.s[31] = this.s[10] + this.s[31]
        this.s[10] = (this.s[10] << 11) | (this.s[10] >> (32 - 11))
        this.s[30] = this.s[11] + this.s[30]
        this.s[11] = (this.s[11] << 11) | (this.s[11] >> (32 - 11))
        this.s[0] ^= this.s[17]
        this.s[1] ^= this.s[16]
        this.s[2] ^= this.s[19]
        this.s[3] ^= this.s[18]
        this.s[4] ^= this.s[21]
        this.s[5] ^= this.s[20]
        this.s[6] ^= this.s[23]
        this.s[7] ^= this.s[22]
        this.s[8] ^= this.s[25]
        this.s[9] ^= this.s[24]
        this.s[10] ^= this.s[27]
        this.s[11] ^= this.s[26]
        this.s[12] ^= this.s[29]
        this.s[13] ^= this.s[28]
        this.s[14] ^= this.s[31]
        this.s[15] ^= this.s[30]
    }
}

func (this *digest256) MarshalBinary() ([]byte, error) {
    x := &this.s
    buf := make([]byte, 128+1, 128+1+this.nx)
    for n := 0; n < 32; n++ {
        PUTU32(buf[n*4:], x[n])
    }

    buf[128] = byte(this.nx)
    return append(buf, this.x[:this.nx]...), nil
}

func (this *digest256) UnmarshalBinary(data []byte) error {
    x := &this.s
    if len(data) < 128+1 {
        return invalidErr
    }

    n := int(data[128])
    if n >= BlockSize256 || len(data) < 128+1+n {
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
