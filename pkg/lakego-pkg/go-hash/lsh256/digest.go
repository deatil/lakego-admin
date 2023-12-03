package lsh256

import (
    "hash"
    "math/bits"
    "encoding/binary"
)

const (
    numStep = 26

    alphaEven = 29
    alphaOdd  = 5

    betaEven = 1
    betaOdd  = 17
)

var (
    iv224 = [...]uint32{
        0x068608D3, 0x62D8F7A7, 0xD76652AB, 0x4C600A43, 0xBDC40AA8, 0x1ECA0B68, 0xDA1A89BE, 0x3147D354,
        0x707EB4F9, 0xF65B3862, 0x6B0B2ABE, 0x56B8EC0A, 0xCF237286, 0xEE0D1727, 0x33636595, 0x8BB8D05F,
    }

    iv256 = [...]uint32{
        0x46a10f1f, 0xfddce486, 0xb41443a8, 0x198e6b9d, 0x3304388d, 0xb0f5a3c7, 0xb36061c4, 0x7adbd553,
        0x105d5378, 0x2f74de54, 0x5c2f2d95, 0xf2553fbe, 0x8051357a, 0x138668c8, 0x47aa4484, 0xe01afb41,
    }

    step = [...]uint32{
        0x917caf90, 0x6c1b10a2, 0x6f352943, 0xcf778243, 0x2ceb7472, 0x29e96ff2, 0x8a9ba428, 0x2eeb2642,
        0x0e2c4021, 0x872bb30e, 0xa45e6cb2, 0x46f9c612, 0x185fe69e, 0x1359621b, 0x263fccb2, 0x1a116870,
        0x3a6c612f, 0xb2dec195, 0x02cb1f56, 0x40bfd858, 0x784684b6, 0x6cbb7d2e, 0x660c7ed8, 0x2b79d88a,
        0xa6cd9069, 0x91a05747, 0xcdea7558, 0x00983098, 0xbecb3b2e, 0x2838ab9a, 0x728b573e, 0xa55262b5,
        0x745dfa0f, 0x31f79ed8, 0xb85fce25, 0x98c8c898, 0x8a0669ec, 0x60e445c2, 0xfde295b0, 0xf7b5185a,
        0xd2580983, 0x29967709, 0x182df3dd, 0x61916130, 0x90705676, 0x452a0822, 0xe07846ad, 0xaccd7351,
        0x2a618d55, 0xc00d8032, 0x4621d0f5, 0xf2f29191, 0x00c6cd06, 0x6f322a67, 0x58bef48d, 0x7a40c4fd,
        0x8beee27f, 0xcd8db2f2, 0x67f2c63b, 0xe5842383, 0xc793d306, 0xa15c91d6, 0x17b381e5, 0xbb05c277,
        0x7ad1620a, 0x5b40a5bf, 0x5ab901a2, 0x69a7a768, 0x5b66d9cd, 0xfdee6877, 0xcb3566fc, 0xc0c83a32,
        0x4c336c84, 0x9be6651a, 0x13baa3fc, 0x114f0fd1, 0xc240a728, 0xec56e074, 0x009c63c7, 0x89026cf2,
        0x7f9ff0d0, 0x824b7fb5, 0xce5ea00f, 0x605ee0e2, 0x02e7cfea, 0x43375560, 0x9d002ac7, 0x8b6f5f7b,
        0x1f90c14f, 0xcdcb3537, 0x2cfeafdd, 0xbf3fc342, 0xeab7b9ec, 0x7a8cb5a3, 0x9d2af264, 0xfacedb06,
        0xb052106e, 0x99006d04, 0x2bae8d09, 0xff030601, 0xa271a6d6, 0x0742591d, 0xc81d5701, 0xc9a9e200,
        0x02627f1e, 0x996d719d, 0xda3b9634, 0x02090800, 0x14187d78, 0x499b7624, 0xe57458c9, 0x738be2c9,
        0x64e19d20, 0x06df0f36, 0x15d1cb0e, 0x0b110802, 0x2c95f58c, 0xe5119a6d, 0x59cd22ae, 0xff6eac3c,
        0x467ebd84, 0xe5ee453c, 0xe79cd923, 0x1c190a0d, 0xc28b81b8, 0xf6ac0852, 0x26efd107, 0x6e1ae93b,
        0xc53c41ca, 0xd4338221, 0x8475fd0a, 0x35231729, 0x4e0d3a7a, 0xa2b45b48, 0x16c0d82d, 0x890424a9,
        0x017e0c8f, 0x07b5a3f5, 0xfa73078e, 0x583a405e, 0x5b47b4c8, 0x570fa3ea, 0xd7990543, 0x8d28ce32,
        0x7f8a9b90, 0xbd5998fc, 0x6d7a9688, 0x927a9eb6, 0xa2fc7d23, 0x66b38e41, 0x709e491a, 0xb5f700bf,
        0x0a262c0f, 0x16f295b9, 0xe8111ef5, 0x0d195548, 0x9f79a0c5, 0x1a41cfa7, 0x0ee7638a, 0xacf7c074,
        0x30523b19, 0x09884ecf, 0xf93014dd, 0x266e9d55, 0x191a6664, 0x5c1176c1, 0xf64aed98, 0xa4b83520,
        0x828d5449, 0x91d71dd8, 0x2944f2d6, 0x950bf27b, 0x3380ca7d, 0x6d88381d, 0x4138868e, 0x5ced55c4,
        0x0fe19dcb, 0x68f4f669, 0x6e37c8ff, 0xa0fe6e10, 0xb44b47b0, 0xf5c0558a, 0x79bf14cf, 0x4a431a20,
        0xf17f68da, 0x5deb5fd1, 0xa600c86d, 0x9f6c7eb0, 0xff92f864, 0xb615e07f, 0x38d3e448, 0x8d5d3a6a,
        0x70e843cb, 0x494b312e, 0xa6c93613, 0x0beb2f4f, 0x928b5d63, 0xcbf66035, 0x0cb82c80, 0xea97a4f7,
        0x592c0f3b, 0x947c5f77, 0x6fff49b9, 0xf71a7e5a, 0x1de8c0f5, 0xc2569600, 0xc4e4ac8c, 0x823c9ce1,
    }

    gamma = [...]int{0, 8, 16, 24, 24, 16, 8, 0}
)

type digest struct {
    cv    [16]uint32
    tcv   [16]uint32
    msg   [16 * (numStep + 1)]uint32
    block [BlockSize]byte

    boff        int
    outlenbytes int
}

func newDigest(size int) hash.Hash {
    ctx := new(digest)
    initDigest(ctx, size)
    return ctx
}

func initDigest(ctx *digest, size int) {
    ctx.outlenbytes = size
    ctx.Reset()
}

func sum(size int, data []byte) [Size]byte {
    var b digest
    initDigest(&b, size)
    b.Reset()
    b.Write(data)

    return b.checkSum()
}

func (b *digest) Size() int {
    return b.outlenbytes
}

func (b *digest) BlockSize() int {
    return BlockSize
}

func (b *digest) Reset() {
    MemsetUint32(b.tcv[:], 0)
    MemsetUint32(b.msg[:], 0)
    MemsetByte(b.block[:], 0)

    b.boff = 0
    switch b.outlenbytes {
    case Size:
        b.cv = iv256
    case Size224:
        b.cv = iv224
    }
}

func (b *digest) Write(p []byte) (n int, err error) {
    if p == nil || len(p) == 0 {
        return
    }
    plen := len(p)

    gap := BlockSize - b.boff
    if b.boff > 0 && len(p) >= gap {
        copy(b.block[b.boff:], p[:gap])
        b.compress(b.block[:])
        b.boff = 0

        p = p[gap:]
    }

    for len(p) >= BlockSize {
        b.compress(p)
        b.boff = 0
        p = p[BlockSize:]
    }

    if len(p) > 0 {
        copy(b.block[b.boff:], p)
        b.boff += len(p)
    }

    return plen, nil
}

func (b *digest) Sum(p []byte) []byte {
    b0 := *b
    hash := b0.checkSum()
    return append(p, hash[:b.Size()]...)
}

func (b *digest) checkSum() [Size]byte {
    b.block[b.boff] = 0x80

    MemsetByte(b.block[b.boff+1:], 0)
    b.compress(b.block[:])

    var temp [8]uint32
    for i := 0; i < 8; i++ {
        temp[i] = b.cv[i] ^ b.cv[i+8]
    }

    var digest [Size]byte
    for i := 0; i < b.outlenbytes; i++ {
        digest[i] = byte(temp[i>>2] >> ((i << 3) & 0x1f))
    }

    return digest
}

func (b *digest) compress(data []byte) {
    b.msgExpansion(data)

    for i := 0; i < numStep/2; i++ {
        b.step(2*i+0, alphaEven, betaEven)
        b.step(2*i+1, alphaOdd, betaOdd)
    }

    for i := 0; i < 16; i++ {
        b.cv[i] ^= b.msg[16*numStep+i]
    }
}

func (b *digest) msgExpansion(in []byte) {
    for i := 0; i < 32; i++ {
        b.msg[i] = binary.LittleEndian.Uint32(in[i*4:])
    }

    for i := 2; i <= numStep; i++ {
        idx := 16 * i
        b.msg[idx] = b.msg[idx-16] + b.msg[idx-29]
        b.msg[idx+1] = b.msg[idx-15] + b.msg[idx-30]
        b.msg[idx+2] = b.msg[idx-14] + b.msg[idx-32]
        b.msg[idx+3] = b.msg[idx-13] + b.msg[idx-31]
        b.msg[idx+4] = b.msg[idx-12] + b.msg[idx-25]
        b.msg[idx+5] = b.msg[idx-11] + b.msg[idx-28]
        b.msg[idx+6] = b.msg[idx-10] + b.msg[idx-27]
        b.msg[idx+7] = b.msg[idx-9] + b.msg[idx-26]
        b.msg[idx+8] = b.msg[idx-8] + b.msg[idx-21]
        b.msg[idx+9] = b.msg[idx-7] + b.msg[idx-22]
        b.msg[idx+10] = b.msg[idx-6] + b.msg[idx-24]
        b.msg[idx+11] = b.msg[idx-5] + b.msg[idx-23]
        b.msg[idx+12] = b.msg[idx-4] + b.msg[idx-17]
        b.msg[idx+13] = b.msg[idx-3] + b.msg[idx-20]
        b.msg[idx+14] = b.msg[idx-2] + b.msg[idx-19]
        b.msg[idx+15] = b.msg[idx-1] + b.msg[idx-18]
    }
}
func (b *digest) step(stepidx, alpha, beta int) {
    var vl, vr uint32

    for colidx := 0; colidx < 8; colidx++ {
        vl = b.cv[colidx] ^ b.msg[16*stepidx+colidx]
        vr = b.cv[colidx+8] ^ b.msg[16*stepidx+colidx+8]
        vl = bits.RotateLeft32(vl+vr, alpha) ^ step[8*stepidx+colidx]
        vr = bits.RotateLeft32(vl+vr, beta)
        b.tcv[colidx] = vr + vl
        b.tcv[colidx+8] = bits.RotateLeft32(vr, gamma[colidx])
    }

    // wordPermutation
    b.cv[0] = b.tcv[6]
    b.cv[1] = b.tcv[4]
    b.cv[2] = b.tcv[5]
    b.cv[3] = b.tcv[7]
    b.cv[4] = b.tcv[12]
    b.cv[5] = b.tcv[15]
    b.cv[6] = b.tcv[14]
    b.cv[7] = b.tcv[13]
    b.cv[8] = b.tcv[2]
    b.cv[9] = b.tcv[0]
    b.cv[10] = b.tcv[1]
    b.cv[11] = b.tcv[3]
    b.cv[12] = b.tcv[8]
    b.cv[13] = b.tcv[11]
    b.cv[14] = b.tcv[10]
    b.cv[15] = b.tcv[9]
}

func MemsetUint32(a []uint32, v uint32) {
    if len(a) == 0 {
        return
    }

    a[0] = v
    for bp := 1; bp < len(a); bp *= 2 {
        copy(a[bp:], a[:bp])
    }
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
