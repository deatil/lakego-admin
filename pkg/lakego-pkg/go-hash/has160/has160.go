package has160

import (
    "hash"
    "math/bits"
    "encoding/binary"
)

// The size of a HAS-160 checksum in bytes.
const Size = 20

// The blocksize of HAS-160 in bytes.
const BlockSize = 64

// New returns a new hash.Hash computing the HAS-160 checksum.
func New() hash.Hash {
    c := new(digest)
    c.Reset()
    return c
}

// Sum returns the HAS-160 checksum of the data.
func Sum(data []byte) (sum [Size]byte) {
    var h digest
    h.Reset()
    h.Write(data)

    hash := h.Sum(nil)
    copy(sum[:], hash)
    return
}

type digest struct {
    H      [5]uint32
    block  [BlockSize]byte
    boff   int
    length int
}

func (this *digest) Size() int {
    return Size
}

func (this *digest) BlockSize() int {
    return BlockSize
}

func (this *digest) Reset() {
    this.boff = 0
    this.length = 0
    copy(this.H[:], initH[:])
}

func (this *digest) Write(p []byte) (n int, err error) {
    if p == nil || len(p) == 0 {
        return
    }

    lenP := len(p)

    this.length += len(p)

    gap := BlockSize - this.boff
    if 0 < this.boff && gap <= len(p) {
        copy(this.block[this.boff:], p[:gap])
        this.stepBlock(this.block[:])
        this.boff = 0
        p = p[gap:]
    }

    for len(p) >= BlockSize {
        this.stepBlock(p)
        this.boff = 0
        p = p[BlockSize:]
    }

    if len(p) > 0 {
        copy(this.block[this.boff:], p)
        this.boff += len(p)
    }

    return lenP, nil
}

func (this *digest) Sum(p []byte) []byte {
    d0 := *this
    hash := d0.checkSum()
    return append(p, hash[:]...)
}

func (this *digest) checkSum() (hash [20]byte) {
    this.block[this.boff] = 0x80
    this.boff++

    if BlockSize-8 < this.boff {
        MemsetByte(this.block[this.boff:], 0)
        this.stepBlock(this.block[:])
        this.boff = 0
    }

    MemsetByte(this.block[this.boff:], 0)
    binary.LittleEndian.PutUint64(this.block[BlockSize-8:], uint64(this.length)*8)
    this.stepBlock(this.block[:])

    binary.LittleEndian.PutUint32(hash[0:], this.H[0])
    binary.LittleEndian.PutUint32(hash[4:], this.H[1])
    binary.LittleEndian.PutUint32(hash[8:], this.H[2])
    binary.LittleEndian.PutUint32(hash[12:], this.H[3])
    binary.LittleEndian.PutUint32(hash[16:], this.H[4])

    return
}

func (this *digest) stepBlock(block []byte) {
    X := [20]uint32{
        binary.LittleEndian.Uint32(block[0:]),
        binary.LittleEndian.Uint32(block[4:]),
        binary.LittleEndian.Uint32(block[8:]),
        binary.LittleEndian.Uint32(block[12:]),
        binary.LittleEndian.Uint32(block[16:]),
        binary.LittleEndian.Uint32(block[20:]),
        binary.LittleEndian.Uint32(block[24:]),
        binary.LittleEndian.Uint32(block[28:]),
        binary.LittleEndian.Uint32(block[32:]),
        binary.LittleEndian.Uint32(block[36:]),
        binary.LittleEndian.Uint32(block[40:]),
        binary.LittleEndian.Uint32(block[44:]),
        binary.LittleEndian.Uint32(block[48:]),
        binary.LittleEndian.Uint32(block[52:]),
        binary.LittleEndian.Uint32(block[56:]),
        binary.LittleEndian.Uint32(block[60:]),
    }
    x := X[:]

    var H [5]uint32
    copy(H[:], this.H[:])
    h := H[:]

    // 00 ~ 19
    // Round 1
    X[16] = X[0] ^ X[1] ^ X[2] ^ X[3]
    X[17] = X[4] ^ X[5] ^ X[6] ^ X[7]
    X[18] = X[8] ^ X[9] ^ X[10] ^ X[11]
    X[19] = X[12] ^ X[13] ^ X[14] ^ X[15]
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
    X[16] = X[3] ^ X[6] ^ X[9] ^ X[12]
    X[17] = X[2] ^ X[5] ^ X[8] ^ X[15]
    X[18] = X[1] ^ X[4] ^ X[11] ^ X[14]
    X[19] = X[0] ^ X[7] ^ X[10] ^ X[13]
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
    X[16] = X[5] ^ X[7] ^ X[12] ^ X[14]
    X[17] = X[0] ^ X[2] ^ X[9] ^ X[11]
    X[18] = X[4] ^ X[6] ^ X[13] ^ X[15]
    X[19] = X[1] ^ X[3] ^ X[8] ^ X[10]
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
    X[16] = X[2] ^ X[7] ^ X[8] ^ X[13]
    X[17] = X[3] ^ X[4] ^ X[9] ^ X[14]
    X[18] = X[0] ^ X[5] ^ X[10] ^ X[15]
    X[19] = X[1] ^ X[6] ^ X[11] ^ X[12]
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

    this.H[0] += h[0]
    this.H[1] += h[1]
    this.H[2] += h[2]
    this.H[3] += h[3]
    this.H[4] += h[4]
}

func f1(h []uint32, a, b, c, d, e int, x []uint32, j int) {
    h[e] += bits.RotateLeft32(h[a], s1[j]) + x[x1[j]] + 0x00000000 + ((h[b] & h[c]) | ((^h[b]) & h[d]))
    h[b] = bits.RotateLeft32(h[b], 10)
}

func f2(h []uint32, a, b, c, d, e int, x []uint32, j int) {
    h[e] += bits.RotateLeft32(h[a], s1[j]) + x[x2[j]] + 0x5a827999 + (h[b] ^ h[c] ^ h[d])
    h[b] = bits.RotateLeft32(h[b], 17)
}

func f3(h []uint32, a, b, c, d, e int, x []uint32, j int) {
    h[e] += bits.RotateLeft32(h[a], s1[j]) + x[x3[j]] + 0x6ed9eba1 + (h[c] ^ (h[b] | (^h[d])))
    h[b] = bits.RotateLeft32(h[b], 25)
}

func f4(h []uint32, a, b, c, d, e int, x []uint32, j int) {
    h[e] += bits.RotateLeft32(h[a], s1[j]) + x[x4[j]] + 0x8f1bbcdc + (h[b] ^ h[c] ^ h[d])
    h[b] = bits.RotateLeft32(h[b], 30)
}

func MemsetByte(a []byte, v byte) {
    if len(a) == 0 {
        return
    }
    a[0] = v
    for bp := 1; bp < len(a); bp *= 2 {
        copy(a[bp:], a[:bp])
    }
}
