package has160

import (
    "hash"
)

// The size of a HAS-160 checksum in bytes.
const Size = 20

// The blocksize of HAS-160 in bytes.
const BlockSize = 64

type digest struct {
    s   [5]uint32
    x   [BlockSize]byte
    nx  int
    len uint64
}

// New returns a new hash.Hash computing the HAS-160 checksum.
func New() hash.Hash {
    c := new(digest)
    c.Reset()
    return c
}

func (this *digest) Size() int {
    return Size
}

func (this *digest) BlockSize() int {
    return BlockSize
}

func (this *digest) Reset() {
    this.nx = 0
    this.len = 0

    this.s = [5]uint32{}
    this.x = [BlockSize]byte{}

    copy(this.s[:], initH[:])
}

func (this *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    plen := len(p)

    var limit = BlockSize
    for this.nx + plen >= limit {
        xx := limit - this.nx

        copy(this.x[this.nx:], p)

        this.stepBlock(this.x[:])

        plen -= xx
        this.len += uint64(xx)

        p = p[xx:]
        this.nx = 0
    }

    copy(this.x[this.nx:], p)
    this.nx += plen
    this.len += uint64(plen)

    return
}

func (this *digest) Sum(p []byte) []byte {
    d0 := *this
    hash := d0.checkSum()
    return append(p, hash[:]...)
}

func (this *digest) checkSum() (hash [20]byte) {
    this.x[this.nx] = 0x80
    this.nx++

    zeros := make([]byte, BlockSize)

    if this.nx > BlockSize - 8 {
        copy(this.x[this.nx:], zeros)
        this.stepBlock(this.x[:])
        this.nx = 0
    }

    copy(this.x[this.nx:], zeros)
    PUTU64(this.x[BlockSize-8:], this.len*8)
    this.stepBlock(this.x[:])

    sum := uint32sToBytes(this.s[:])
    copy(hash[:], sum)

    return
}

func (this *digest) stepBlock(block []byte) {
    x := make([]uint32, 20)
    blocks := bytesToUint32s(block)
    copy(x, blocks)

    var H [5]uint32
    copy(H[:], this.s[:])
    h := H[:]

    // 00 ~ 19
    // Round 1
    x[16] = x[0] ^ x[1] ^ x[2] ^ x[3]
    x[17] = x[4] ^ x[5] ^ x[6] ^ x[7]
    x[18] = x[8] ^ x[9] ^ x[10] ^ x[11]
    x[19] = x[12] ^ x[13] ^ x[14] ^ x[15]
    for i := 0; i < 20; i++ {
        f1(h[:], 4-(4+i)%5, 4-(3+i)%5, 4-(2+i)%5, 4-(1+i)%5, 4-i%5, x, i)  // j = 00 + i
    }

    // 20 ~ 39
    // Round 2
    x[16] = x[3] ^ x[6] ^ x[9] ^ x[12]
    x[17] = x[2] ^ x[5] ^ x[8] ^ x[15]
    x[18] = x[1] ^ x[4] ^ x[11] ^ x[14]
    x[19] = x[0] ^ x[7] ^ x[10] ^ x[13]
    for i := 0; i < 20; i++ {
        f2(h[:], 4-(4+i)%5, 4-(3+i)%5, 4-(2+i)%5, 4-(1+i)%5, 4-i%5, x, i)  // j = 20 + i
    }

    // 40 ~ 59
    // Round 3
    x[16] = x[5] ^ x[7] ^ x[12] ^ x[14]
    x[17] = x[0] ^ x[2] ^ x[9] ^ x[11]
    x[18] = x[4] ^ x[6] ^ x[13] ^ x[15]
    x[19] = x[1] ^ x[3] ^ x[8] ^ x[10]
    for i := 0; i < 20; i++ {
        f3(h[:], 4-(4+i)%5, 4-(3+i)%5, 4-(2+i)%5, 4-(1+i)%5, 4-i%5, x, i)  // j = 40 + i
    }

    // 60 ~ 79
    // Round 4
    x[16] = x[2] ^ x[7] ^ x[8] ^ x[13]
    x[17] = x[3] ^ x[4] ^ x[9] ^ x[14]
    x[18] = x[0] ^ x[5] ^ x[10] ^ x[15]
    x[19] = x[1] ^ x[6] ^ x[11] ^ x[12]
    for i := 0; i < 20; i++ {
        f4(h[:], 4-(4+i)%5, 4-(3+i)%5, 4-(2+i)%5, 4-(1+i)%5, 4-i%5, x, i)  // j = 60 + i
    }

    this.s[0] += h[0]
    this.s[1] += h[1]
    this.s[2] += h[2]
    this.s[3] += h[3]
    this.s[4] += h[4]
}
