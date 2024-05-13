package luffa

const (
    // hash size
    Size224 = 28
    Size256 = 32

    BlockSize = 32
)

// digest384 represents the partial evaluation of a checksum.
type digest256 struct {
    s   [24]uint32
    x   [BlockSize]byte
    nx  int
    len uint64

    hs int

    V00, V01, V02, V03, V04, V05, V06, V07 uint32
    V10, V11, V12, V13, V14, V15, V16, V17 uint32
    V20, V21, V22, V23, V24, V25, V26, V27 uint32
    tmpBuf [32]byte
}

// newDigest256 returns a new *digest256 computing the luffa checksum
func newDigest256(hs int) *digest256 {
    d := new(digest256)
    d.hs = hs
    d.Reset()

    return d
}

func (d *digest256) Reset() {
    d.s = [24]uint32{}
    d.x = [BlockSize]byte{}

    d.nx = 0
    d.len = 0

    d.tmpBuf = [32]byte{}

    d.V00 = IV_256[ 0]
    d.V01 = IV_256[ 1]
    d.V02 = IV_256[ 2]
    d.V03 = IV_256[ 3]
    d.V04 = IV_256[ 4]
    d.V05 = IV_256[ 5]
    d.V06 = IV_256[ 6]
    d.V07 = IV_256[ 7]
    d.V10 = IV_256[ 8]
    d.V11 = IV_256[ 9]
    d.V12 = IV_256[10]
    d.V13 = IV_256[11]
    d.V14 = IV_256[12]
    d.V15 = IV_256[13]
    d.V16 = IV_256[14]
    d.V17 = IV_256[15]
    d.V20 = IV_256[16]
    d.V21 = IV_256[17]
    d.V22 = IV_256[18]
    d.V23 = IV_256[19]
    d.V24 = IV_256[20]
    d.V25 = IV_256[21]
    d.V26 = IV_256[22]
    d.V27 = IV_256[23]
}

func (d *digest256) Size() int {
    return d.hs
}

func (d *digest256) BlockSize() int {
    return BlockSize
}

func (d *digest256) Write(p []byte) (nn int, err error) {
    nn = len(p)

    d.len += uint64(nn)

    plen := len(p)

    for d.nx + plen >= BlockSize {
        copy(d.x[d.nx:], p)

        d.processBlock(d.x[:])

        xx := BlockSize - d.nx
        plen -= xx

        p = p[xx:]
        d.nx = 0
    }

    copy(d.x[d.nx:], p)
    d.nx += plen

    return
}

func (d *digest256) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *digest256) checkSum() (out []byte) {
    ptr := d.nx

    d.tmpBuf[ptr] = 0x80
    for i := ptr + 1; i < 32; i++ {
        d.tmpBuf[i] = 0x00
    }

    d.Write(d.tmpBuf[ptr:])

    for i := 0; i < ptr + 1; i++ {
        d.tmpBuf[i] = 0x00
    }
    d.Write(d.tmpBuf[:])

    if d.hs == 32 {
        out = make([]byte, 32)
    } else {
        out = make([]byte, 28)
    }

    putu32(out[0:], d.V00 ^ d.V10 ^ d.V20)
    putu32(out[4:], d.V01 ^ d.V11 ^ d.V21)
    putu32(out[8:], d.V02 ^ d.V12 ^ d.V22)
    putu32(out[12:], d.V03 ^ d.V13 ^ d.V23)
    putu32(out[16:], d.V04 ^ d.V14 ^ d.V24)
    putu32(out[20:], d.V05 ^ d.V15 ^ d.V25)
    putu32(out[24:], d.V06 ^ d.V16 ^ d.V26)

    if d.hs == 32 {
        putu32(out[28:], d.V07 ^ d.V17 ^ d.V27)
    }

    return
}

func (d *digest256) processBlock(data []byte) {
    var tmp uint32
    var a0, a1, a2, a3, a4, a5, a6, a7 uint32

    var M0 = getu32(data[0:])
    var M1 = getu32(data[4:])
    var M2 = getu32(data[8:])
    var M3 = getu32(data[12:])
    var M4 = getu32(data[16:])
    var M5 = getu32(data[20:])
    var M6 = getu32(data[24:])
    var M7 = getu32(data[28:])

    V00 := d.V00
    V01 := d.V01
    V02 := d.V02
    V03 := d.V03
    V04 := d.V04
    V05 := d.V05
    V06 := d.V06
    V07 := d.V07
    V10 := d.V10
    V11 := d.V11
    V12 := d.V12
    V13 := d.V13
    V14 := d.V14
    V15 := d.V15
    V16 := d.V16
    V17 := d.V17
    V20 := d.V20
    V21 := d.V21
    V22 := d.V22
    V23 := d.V23
    V24 := d.V24
    V25 := d.V25
    V26 := d.V26
    V27 := d.V27

    a0 = V00 ^ V10
    a1 = V01 ^ V11
    a2 = V02 ^ V12
    a3 = V03 ^ V13
    a4 = V04 ^ V14
    a5 = V05 ^ V15
    a6 = V06 ^ V16
    a7 = V07 ^ V17
    a0 = a0 ^ V20
    a1 = a1 ^ V21
    a2 = a2 ^ V22
    a3 = a3 ^ V23
    a4 = a4 ^ V24
    a5 = a5 ^ V25
    a6 = a6 ^ V26
    a7 = a7 ^ V27
    tmp = a7
    a7 = a6
    a6 = a5
    a5 = a4
    a4 = a3 ^ tmp
    a3 = a2 ^ tmp
    a2 = a1
    a1 = a0 ^ tmp
    a0 = tmp
    V00 = a0 ^ V00
    V01 = a1 ^ V01
    V02 = a2 ^ V02
    V03 = a3 ^ V03
    V04 = a4 ^ V04
    V05 = a5 ^ V05
    V06 = a6 ^ V06
    V07 = a7 ^ V07
    V00 = M0 ^ V00
    V01 = M1 ^ V01
    V02 = M2 ^ V02
    V03 = M3 ^ V03
    V04 = M4 ^ V04
    V05 = M5 ^ V05
    V06 = M6 ^ V06
    V07 = M7 ^ V07
    tmp = M7
    M7 = M6
    M6 = M5
    M5 = M4
    M4 = M3 ^ tmp
    M3 = M2 ^ tmp
    M2 = M1
    M1 = M0 ^ tmp
    M0 = tmp
    V10 = a0 ^ V10
    V11 = a1 ^ V11
    V12 = a2 ^ V12
    V13 = a3 ^ V13
    V14 = a4 ^ V14
    V15 = a5 ^ V15
    V16 = a6 ^ V16
    V17 = a7 ^ V17
    V10 = M0 ^ V10
    V11 = M1 ^ V11
    V12 = M2 ^ V12
    V13 = M3 ^ V13
    V14 = M4 ^ V14
    V15 = M5 ^ V15
    V16 = M6 ^ V16
    V17 = M7 ^ V17
    tmp = M7
    M7 = M6
    M6 = M5
    M5 = M4
    M4 = M3 ^ tmp
    M3 = M2 ^ tmp
    M2 = M1
    M1 = M0 ^ tmp
    M0 = tmp
    V20 = a0 ^ V20
    V21 = a1 ^ V21
    V22 = a2 ^ V22
    V23 = a3 ^ V23
    V24 = a4 ^ V24
    V25 = a5 ^ V25
    V26 = a6 ^ V26
    V27 = a7 ^ V27
    V20 = M0 ^ V20
    V21 = M1 ^ V21
    V22 = M2 ^ V22
    V23 = M3 ^ V23
    V24 = M4 ^ V24
    V25 = M5 ^ V25
    V26 = M6 ^ V26
    V27 = M7 ^ V27
    V14 = (V14 << 1) | (V14 >> 31)
    V15 = (V15 << 1) | (V15 >> 31)
    V16 = (V16 << 1) | (V16 >> 31)
    V17 = (V17 << 1) | (V17 >> 31)
    V24 = (V24 << 2) | (V24 >> 30)
    V25 = (V25 << 2) | (V25 >> 30)
    V26 = (V26 << 2) | (V26 >> 30)
    V27 = (V27 << 2) | (V27 >> 30)

    for r := 0; r < 8; r++ {
        tmp = V00
        V00 |= V01
        V02 ^= V03
        V01 = ^V01
        V00 ^= V03
        V03 &= tmp
        V01 ^= V03
        V03 ^= V02
        V02 &= V00
        V00 = ^V00
        V02 ^= V01
        V01 |= V03
        tmp ^= V01
        V03 ^= V02
        V02 &= V01
        V01 ^= V00
        V00 = tmp
        tmp = V05
        V05 |= V06
        V07 ^= V04
        V06 = ^V06
        V05 ^= V04
        V04 &= tmp
        V06 ^= V04
        V04 ^= V07
        V07 &= V05
        V05 = ^V05
        V07 ^= V06
        V06 |= V04
        tmp ^= V06
        V04 ^= V07
        V07 &= V06
        V06 ^= V05
        V05 = tmp
        V04 ^= V00
        V00 = ((V00 << 2) | (V00 >> 30)) ^ V04
        V04 = ((V04 << 14) | (V04 >> 18)) ^ V00
        V00 = ((V00 << 10) | (V00 >> 22)) ^ V04
        V04 = (V04 << 1) | (V04 >> 31)
        V05 ^= V01
        V01 = ((V01 << 2) | (V01 >> 30)) ^ V05
        V05 = ((V05 << 14) | (V05 >> 18)) ^ V01
        V01 = ((V01 << 10) | (V01 >> 22)) ^ V05
        V05 = (V05 << 1) | (V05 >> 31)
        V06 ^= V02
        V02 = ((V02 << 2) | (V02 >> 30)) ^ V06
        V06 = ((V06 << 14) | (V06 >> 18)) ^ V02
        V02 = ((V02 << 10) | (V02 >> 22)) ^ V06
        V06 = (V06 << 1) | (V06 >> 31)
        V07 ^= V03
        V03 = ((V03 << 2) | (V03 >> 30)) ^ V07
        V07 = ((V07 << 14) | (V07 >> 18)) ^ V03
        V03 = ((V03 << 10) | (V03 >> 22)) ^ V07
        V07 = (V07 << 1) | (V07 >> 31)
        V00 ^= RC00_256[r]
        V04 ^= RC04_256[r]
    }

    for r := 0; r < 8; r++ {
        tmp = V10
        V10 |= V11
        V12 ^= V13
        V11 = ^V11
        V10 ^= V13
        V13 &= tmp
        V11 ^= V13
        V13 ^= V12
        V12 &= V10
        V10 = ^V10
        V12 ^= V11
        V11 |= V13
        tmp ^= V11
        V13 ^= V12
        V12 &= V11
        V11 ^= V10
        V10 = tmp
        tmp = V15
        V15 |= V16
        V17 ^= V14
        V16 = ^V16
        V15 ^= V14
        V14 &= tmp
        V16 ^= V14
        V14 ^= V17
        V17 &= V15
        V15 = ^V15
        V17 ^= V16
        V16 |= V14
        tmp ^= V16
        V14 ^= V17
        V17 &= V16
        V16 ^= V15
        V15 = tmp
        V14 ^= V10
        V10 = ((V10 << 2) | (V10 >> 30)) ^ V14
        V14 = ((V14 << 14) | (V14 >> 18)) ^ V10
        V10 = ((V10 << 10) | (V10 >> 22)) ^ V14
        V14 = (V14 << 1) | (V14 >> 31)
        V15 ^= V11
        V11 = ((V11 << 2) | (V11 >> 30)) ^ V15
        V15 = ((V15 << 14) | (V15 >> 18)) ^ V11
        V11 = ((V11 << 10) | (V11 >> 22)) ^ V15
        V15 = (V15 << 1) | (V15 >> 31)
        V16 ^= V12
        V12 = ((V12 << 2) | (V12 >> 30)) ^ V16
        V16 = ((V16 << 14) | (V16 >> 18)) ^ V12
        V12 = ((V12 << 10) | (V12 >> 22)) ^ V16
        V16 = (V16 << 1) | (V16 >> 31)
        V17 ^= V13
        V13 = ((V13 << 2) | (V13 >> 30)) ^ V17
        V17 = ((V17 << 14) | (V17 >> 18)) ^ V13
        V13 = ((V13 << 10) | (V13 >> 22)) ^ V17
        V17 = (V17 << 1) | (V17 >> 31)
        V10 ^= RC10_256[r]
        V14 ^= RC14_256[r]
    }

    for r := 0; r < 8; r++ {
        tmp = V20
        V20 |= V21
        V22 ^= V23
        V21 = ^V21
        V20 ^= V23
        V23 &= tmp
        V21 ^= V23
        V23 ^= V22
        V22 &= V20
        V20 = ^V20
        V22 ^= V21
        V21 |= V23
        tmp ^= V21
        V23 ^= V22
        V22 &= V21
        V21 ^= V20
        V20 = tmp
        tmp = V25
        V25 |= V26
        V27 ^= V24
        V26 = ^V26
        V25 ^= V24
        V24 &= tmp
        V26 ^= V24
        V24 ^= V27
        V27 &= V25
        V25 = ^V25
        V27 ^= V26
        V26 |= V24
        tmp ^= V26
        V24 ^= V27
        V27 &= V26
        V26 ^= V25
        V25 = tmp
        V24 ^= V20
        V20 = ((V20 << 2) | (V20 >> 30)) ^ V24
        V24 = ((V24 << 14) | (V24 >> 18)) ^ V20
        V20 = ((V20 << 10) | (V20 >> 22)) ^ V24
        V24 = (V24 << 1) | (V24 >> 31)
        V25 ^= V21
        V21 = ((V21 << 2) | (V21 >> 30)) ^ V25
        V25 = ((V25 << 14) | (V25 >> 18)) ^ V21
        V21 = ((V21 << 10) | (V21 >> 22)) ^ V25
        V25 = (V25 << 1) | (V25 >> 31)
        V26 ^= V22
        V22 = ((V22 << 2) | (V22 >> 30)) ^ V26
        V26 = ((V26 << 14) | (V26 >> 18)) ^ V22
        V22 = ((V22 << 10) | (V22 >> 22)) ^ V26
        V26 = (V26 << 1) | (V26 >> 31)
        V27 ^= V23
        V23 = ((V23 << 2) | (V23 >> 30)) ^ V27
        V27 = ((V27 << 14) | (V27 >> 18)) ^ V23
        V23 = ((V23 << 10) | (V23 >> 22)) ^ V27
        V27 = (V27 << 1) | (V27 >> 31)
        V20 ^= RC20_256[r]
        V24 ^= RC24_256[r]
    }

    d.V00 = V00
    d.V01 = V01
    d.V02 = V02
    d.V03 = V03
    d.V04 = V04
    d.V05 = V05
    d.V06 = V06
    d.V07 = V07
    d.V10 = V10
    d.V11 = V11
    d.V12 = V12
    d.V13 = V13
    d.V14 = V14
    d.V15 = V15
    d.V16 = V16
    d.V17 = V17
    d.V20 = V20
    d.V21 = V21
    d.V22 = V22
    d.V23 = V23
    d.V24 = V24
    d.V25 = V25
    d.V26 = V26
    d.V27 = V27
}
