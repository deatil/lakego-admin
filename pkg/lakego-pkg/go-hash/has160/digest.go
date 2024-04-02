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

    /*
    for i := 0; i < 20; i++ {
        f1(h[:], 4-(4+i)%5, 4-(3+i)%5, 4-(2+i)%5, 4-(1+i)%5, 4-i%5, x, i)  // j = 00 + i
    }
    */

    // 00 ~ 19
    // Round 1
    x[16] = x[0] ^ x[1] ^ x[2] ^ x[3]
    x[17] = x[4] ^ x[5] ^ x[6] ^ x[7]
    x[18] = x[8] ^ x[9] ^ x[10] ^ x[11]
    x[19] = x[12] ^ x[13] ^ x[14] ^ x[15]
    f1(h, 0, 1, 2, 3, 4, x, 0)  // j = 00
    f1(h, 4, 0, 1, 2, 3, x, 1)  // j = 01
    f1(h, 3, 4, 0, 1, 2, x, 2)  // j = 02
    f1(h, 2, 3, 4, 0, 1, x, 3)  // j = 03
    f1(h, 1, 2, 3, 4, 0, x, 4)  // j = 04
    f1(h, 0, 1, 2, 3, 4, x, 5)  // j = 05
    f1(h, 4, 0, 1, 2, 3, x, 6)  // j = 06
    f1(h, 3, 4, 0, 1, 2, x, 7)  // j = 07
    f1(h, 2, 3, 4, 0, 1, x, 8)  // j = 08
    f1(h, 1, 2, 3, 4, 0, x, 9)  // j = 09
    f1(h, 0, 1, 2, 3, 4, x, 10) // j = 10
    f1(h, 4, 0, 1, 2, 3, x, 11) // j = 11
    f1(h, 3, 4, 0, 1, 2, x, 12) // j = 12
    f1(h, 2, 3, 4, 0, 1, x, 13) // j = 13
    f1(h, 1, 2, 3, 4, 0, x, 14) // j = 14
    f1(h, 0, 1, 2, 3, 4, x, 15) // j = 15
    f1(h, 4, 0, 1, 2, 3, x, 16) // j = 16
    f1(h, 3, 4, 0, 1, 2, x, 17) // j = 17
    f1(h, 2, 3, 4, 0, 1, x, 18) // j = 18
    f1(h, 1, 2, 3, 4, 0, x, 19) // j = 19

    // 20 ~ 39
    // Round 2
    x[16] = x[3] ^ x[6] ^ x[9] ^ x[12]
    x[17] = x[2] ^ x[5] ^ x[8] ^ x[15]
    x[18] = x[1] ^ x[4] ^ x[11] ^ x[14]
    x[19] = x[0] ^ x[7] ^ x[10] ^ x[13]
    f2(h, 0, 1, 2, 3, 4, x, 0)  // j = 20
    f2(h, 4, 0, 1, 2, 3, x, 1)  // j = 21
    f2(h, 3, 4, 0, 1, 2, x, 2)  // j = 22
    f2(h, 2, 3, 4, 0, 1, x, 3)  // j = 23
    f2(h, 1, 2, 3, 4, 0, x, 4)  // j = 24
    f2(h, 0, 1, 2, 3, 4, x, 5)  // j = 25
    f2(h, 4, 0, 1, 2, 3, x, 6)  // j = 26
    f2(h, 3, 4, 0, 1, 2, x, 7)  // j = 27
    f2(h, 2, 3, 4, 0, 1, x, 8)  // j = 28
    f2(h, 1, 2, 3, 4, 0, x, 9)  // j = 29
    f2(h, 0, 1, 2, 3, 4, x, 10) // j = 30
    f2(h, 4, 0, 1, 2, 3, x, 11) // j = 31
    f2(h, 3, 4, 0, 1, 2, x, 12) // j = 32
    f2(h, 2, 3, 4, 0, 1, x, 13) // j = 33
    f2(h, 1, 2, 3, 4, 0, x, 14) // j = 34
    f2(h, 0, 1, 2, 3, 4, x, 15) // j = 35
    f2(h, 4, 0, 1, 2, 3, x, 16) // j = 36
    f2(h, 3, 4, 0, 1, 2, x, 17) // j = 37
    f2(h, 2, 3, 4, 0, 1, x, 18) // j = 38
    f2(h, 1, 2, 3, 4, 0, x, 19) // j = 39

    // 40 ~ 59
    // Round 3
    x[16] = x[5] ^ x[7] ^ x[12] ^ x[14]
    x[17] = x[0] ^ x[2] ^ x[9] ^ x[11]
    x[18] = x[4] ^ x[6] ^ x[13] ^ x[15]
    x[19] = x[1] ^ x[3] ^ x[8] ^ x[10]
    f3(h, 0, 1, 2, 3, 4, x, 0)  // j = 40
    f3(h, 4, 0, 1, 2, 3, x, 1)  // j = 41
    f3(h, 3, 4, 0, 1, 2, x, 2)  // j = 42
    f3(h, 2, 3, 4, 0, 1, x, 3)  // j = 43
    f3(h, 1, 2, 3, 4, 0, x, 4)  // j = 44
    f3(h, 0, 1, 2, 3, 4, x, 5)  // j = 45
    f3(h, 4, 0, 1, 2, 3, x, 6)  // j = 46
    f3(h, 3, 4, 0, 1, 2, x, 7)  // j = 47
    f3(h, 2, 3, 4, 0, 1, x, 8)  // j = 48
    f3(h, 1, 2, 3, 4, 0, x, 9)  // j = 49
    f3(h, 0, 1, 2, 3, 4, x, 10) // j = 50
    f3(h, 4, 0, 1, 2, 3, x, 11) // j = 51
    f3(h, 3, 4, 0, 1, 2, x, 12) // j = 52
    f3(h, 2, 3, 4, 0, 1, x, 13) // j = 53
    f3(h, 1, 2, 3, 4, 0, x, 14) // j = 54
    f3(h, 0, 1, 2, 3, 4, x, 15) // j = 55
    f3(h, 4, 0, 1, 2, 3, x, 16) // j = 56
    f3(h, 3, 4, 0, 1, 2, x, 17) // j = 57
    f3(h, 2, 3, 4, 0, 1, x, 18) // j = 58
    f3(h, 1, 2, 3, 4, 0, x, 19) // j = 59


    // 60 ~ 79
    // Round 4
    x[16] = x[2] ^ x[7] ^ x[8] ^ x[13]
    x[17] = x[3] ^ x[4] ^ x[9] ^ x[14]
    x[18] = x[0] ^ x[5] ^ x[10] ^ x[15]
    x[19] = x[1] ^ x[6] ^ x[11] ^ x[12]
    f4(h, 0, 1, 2, 3, 4, x, 0)  // j = 60
    f4(h, 4, 0, 1, 2, 3, x, 1)  // j = 61
    f4(h, 3, 4, 0, 1, 2, x, 2)  // j = 62
    f4(h, 2, 3, 4, 0, 1, x, 3)  // j = 63
    f4(h, 1, 2, 3, 4, 0, x, 4)  // j = 64
    f4(h, 0, 1, 2, 3, 4, x, 5)  // j = 65
    f4(h, 4, 0, 1, 2, 3, x, 6)  // j = 66
    f4(h, 3, 4, 0, 1, 2, x, 7)  // j = 67
    f4(h, 2, 3, 4, 0, 1, x, 8)  // j = 68
    f4(h, 1, 2, 3, 4, 0, x, 9)  // j = 69
    f4(h, 0, 1, 2, 3, 4, x, 10) // j = 70
    f4(h, 4, 0, 1, 2, 3, x, 11) // j = 71
    f4(h, 3, 4, 0, 1, 2, x, 12) // j = 72
    f4(h, 2, 3, 4, 0, 1, x, 13) // j = 73
    f4(h, 1, 2, 3, 4, 0, x, 14) // j = 74
    f4(h, 0, 1, 2, 3, 4, x, 15) // j = 75
    f4(h, 4, 0, 1, 2, 3, x, 16) // j = 76
    f4(h, 3, 4, 0, 1, 2, x, 17) // j = 77
    f4(h, 2, 3, 4, 0, 1, x, 18) // j = 78
    f4(h, 1, 2, 3, 4, 0, x, 19) // j = 79

    this.s[0] += h[0]
    this.s[1] += h[1]
    this.s[2] += h[2]
    this.s[3] += h[3]
    this.s[4] += h[4]
}
