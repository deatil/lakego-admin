package luffa

const (
    // hash size
    Size512 = 64
)

// digest512 represents the partial evaluation of a checksum.
type digest512 struct {
    s   [40]uint32
    x   [BlockSize]byte
    nx  int
    len uint64

    V00, V01, V02, V03, V04, V05, V06, V07 uint32
    V10, V11, V12, V13, V14, V15, V16, V17 uint32
    V20, V21, V22, V23, V24, V25, V26, V27 uint32
    V30, V31, V32, V33, V34, V35, V36, V37 uint32
    V40, V41, V42, V43, V44, V45, V46, V47 uint32
    tmpBuf [32]byte
}

// newDigest512 returns a new *digest512 computing the luffa checksum
func newDigest512() *digest512 {
    d := new(digest512)
    d.Reset()

    return d
}

func (d *digest512) Reset() {
    d.s = [40]uint32{}
    d.x = [BlockSize]byte{}

    d.nx = 0
    d.len = 0

    d.tmpBuf = [32]byte{}

    d.V00 = IV_512[ 0]
    d.V01 = IV_512[ 1]
    d.V02 = IV_512[ 2]
    d.V03 = IV_512[ 3]
    d.V04 = IV_512[ 4]
    d.V05 = IV_512[ 5]
    d.V06 = IV_512[ 6]
    d.V07 = IV_512[ 7]
    d.V10 = IV_512[ 8]
    d.V11 = IV_512[ 9]
    d.V12 = IV_512[10]
    d.V13 = IV_512[11]
    d.V14 = IV_512[12]
    d.V15 = IV_512[13]
    d.V16 = IV_512[14]
    d.V17 = IV_512[15]
    d.V20 = IV_512[16]
    d.V21 = IV_512[17]
    d.V22 = IV_512[18]
    d.V23 = IV_512[19]
    d.V24 = IV_512[20]
    d.V25 = IV_512[21]
    d.V26 = IV_512[22]
    d.V27 = IV_512[23]
    d.V30 = IV_512[24]
    d.V31 = IV_512[25]
    d.V32 = IV_512[26]
    d.V33 = IV_512[27]
    d.V34 = IV_512[28]
    d.V35 = IV_512[29]
    d.V36 = IV_512[30]
    d.V37 = IV_512[31]
    d.V40 = IV_512[32]
    d.V41 = IV_512[33]
    d.V42 = IV_512[34]
    d.V43 = IV_512[35]
    d.V44 = IV_512[36]
    d.V45 = IV_512[37]
    d.V46 = IV_512[38]
    d.V47 = IV_512[39]
}

func (d *digest512) Size() int {
    return Size512
}

func (d *digest512) BlockSize() int {
    return BlockSize
}

func (d *digest512) Write(p []byte) (nn int, err error) {
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

func (d *digest512) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *digest512) checkSum() (out []byte) {
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

    out = make([]byte, 64)

    putu32(out[0:], d.V00 ^ d.V10 ^ d.V20 ^ d.V30 ^ d.V40)
    putu32(out[4:], d.V01 ^ d.V11 ^ d.V21 ^ d.V31 ^ d.V41)
    putu32(out[8:], d.V02 ^ d.V12 ^ d.V22 ^ d.V32 ^ d.V42)
    putu32(out[12:], d.V03 ^ d.V13 ^ d.V23 ^ d.V33 ^ d.V43)
    putu32(out[16:], d.V04 ^ d.V14 ^ d.V24 ^ d.V34 ^ d.V44)
    putu32(out[20:], d.V05 ^ d.V15 ^ d.V25 ^ d.V35 ^ d.V45)
    putu32(out[24:], d.V06 ^ d.V16 ^ d.V26 ^ d.V36 ^ d.V46)
    putu32(out[28:], d.V07 ^ d.V17 ^ d.V27 ^ d.V37 ^ d.V47)

    d.Write(d.tmpBuf[:])

    putu32(out[32:], d.V00 ^ d.V10 ^ d.V20 ^ d.V30 ^ d.V40)
    putu32(out[36:], d.V01 ^ d.V11 ^ d.V21 ^ d.V31 ^ d.V41)
    putu32(out[40:], d.V02 ^ d.V12 ^ d.V22 ^ d.V32 ^ d.V42)
    putu32(out[44:], d.V03 ^ d.V13 ^ d.V23 ^ d.V33 ^ d.V43)
    putu32(out[48:], d.V04 ^ d.V14 ^ d.V24 ^ d.V34 ^ d.V44)
    putu32(out[52:], d.V05 ^ d.V15 ^ d.V25 ^ d.V35 ^ d.V45)
    putu32(out[56:], d.V06 ^ d.V16 ^ d.V26 ^ d.V36 ^ d.V46)
    putu32(out[60:], d.V07 ^ d.V17 ^ d.V27 ^ d.V37 ^ d.V47)

    return
}

func (d *digest512) processBlock(data []byte) {
    var tmp uint32
    var a0, a1, a2, a3, a4, a5, a6, a7 uint32
    var b0, b1, b2, b3, b4, b5, b6, b7 uint32

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
    V30 := d.V30
    V31 := d.V31
    V32 := d.V32
    V33 := d.V33
    V34 := d.V34
    V35 := d.V35
    V36 := d.V36
    V37 := d.V37
    V40 := d.V40
    V41 := d.V41
    V42 := d.V42
    V43 := d.V43
    V44 := d.V44
    V45 := d.V45
    V46 := d.V46
    V47 := d.V47

    a0 = V00 ^ V10
    a1 = V01 ^ V11
    a2 = V02 ^ V12
    a3 = V03 ^ V13
    a4 = V04 ^ V14
    a5 = V05 ^ V15
    a6 = V06 ^ V16
    a7 = V07 ^ V17
    b0 = V20 ^ V30
    b1 = V21 ^ V31
    b2 = V22 ^ V32
    b3 = V23 ^ V33
    b4 = V24 ^ V34
    b5 = V25 ^ V35
    b6 = V26 ^ V36
    b7 = V27 ^ V37
    a0 = a0 ^ b0
    a1 = a1 ^ b1
    a2 = a2 ^ b2
    a3 = a3 ^ b3
    a4 = a4 ^ b4
    a5 = a5 ^ b5
    a6 = a6 ^ b6
    a7 = a7 ^ b7
    a0 = a0 ^ V40
    a1 = a1 ^ V41
    a2 = a2 ^ V42
    a3 = a3 ^ V43
    a4 = a4 ^ V44
    a5 = a5 ^ V45
    a6 = a6 ^ V46
    a7 = a7 ^ V47
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
    V10 = a0 ^ V10
    V11 = a1 ^ V11
    V12 = a2 ^ V12
    V13 = a3 ^ V13
    V14 = a4 ^ V14
    V15 = a5 ^ V15
    V16 = a6 ^ V16
    V17 = a7 ^ V17
    V20 = a0 ^ V20
    V21 = a1 ^ V21
    V22 = a2 ^ V22
    V23 = a3 ^ V23
    V24 = a4 ^ V24
    V25 = a5 ^ V25
    V26 = a6 ^ V26
    V27 = a7 ^ V27
    V30 = a0 ^ V30
    V31 = a1 ^ V31
    V32 = a2 ^ V32
    V33 = a3 ^ V33
    V34 = a4 ^ V34
    V35 = a5 ^ V35
    V36 = a6 ^ V36
    V37 = a7 ^ V37
    V40 = a0 ^ V40
    V41 = a1 ^ V41
    V42 = a2 ^ V42
    V43 = a3 ^ V43
    V44 = a4 ^ V44
    V45 = a5 ^ V45
    V46 = a6 ^ V46
    V47 = a7 ^ V47
    tmp = V07
    b7 = V06
    b6 = V05
    b5 = V04
    b4 = V03 ^ tmp
    b3 = V02 ^ tmp
    b2 = V01
    b1 = V00 ^ tmp
    b0 = tmp
    b0 = b0 ^ V10
    b1 = b1 ^ V11
    b2 = b2 ^ V12
    b3 = b3 ^ V13
    b4 = b4 ^ V14
    b5 = b5 ^ V15
    b6 = b6 ^ V16
    b7 = b7 ^ V17
    tmp = V17
    V17 = V16
    V16 = V15
    V15 = V14
    V14 = V13 ^ tmp
    V13 = V12 ^ tmp
    V12 = V11
    V11 = V10 ^ tmp
    V10 = tmp
    V10 = V10 ^ V20
    V11 = V11 ^ V21
    V12 = V12 ^ V22
    V13 = V13 ^ V23
    V14 = V14 ^ V24
    V15 = V15 ^ V25
    V16 = V16 ^ V26
    V17 = V17 ^ V27
    tmp = V27
    V27 = V26
    V26 = V25
    V25 = V24
    V24 = V23 ^ tmp
    V23 = V22 ^ tmp
    V22 = V21
    V21 = V20 ^ tmp
    V20 = tmp
    V20 = V20 ^ V30
    V21 = V21 ^ V31
    V22 = V22 ^ V32
    V23 = V23 ^ V33
    V24 = V24 ^ V34
    V25 = V25 ^ V35
    V26 = V26 ^ V36
    V27 = V27 ^ V37
    tmp = V37
    V37 = V36
    V36 = V35
    V35 = V34
    V34 = V33 ^ tmp
    V33 = V32 ^ tmp
    V32 = V31
    V31 = V30 ^ tmp
    V30 = tmp
    V30 = V30 ^ V40
    V31 = V31 ^ V41
    V32 = V32 ^ V42
    V33 = V33 ^ V43
    V34 = V34 ^ V44
    V35 = V35 ^ V45
    V36 = V36 ^ V46
    V37 = V37 ^ V47
    tmp = V47
    V47 = V46
    V46 = V45
    V45 = V44
    V44 = V43 ^ tmp
    V43 = V42 ^ tmp
    V42 = V41
    V41 = V40 ^ tmp
    V40 = tmp
    V40 = V40 ^ V00
    V41 = V41 ^ V01
    V42 = V42 ^ V02
    V43 = V43 ^ V03
    V44 = V44 ^ V04
    V45 = V45 ^ V05
    V46 = V46 ^ V06
    V47 = V47 ^ V07
    tmp = b7
    V07 = b6
    V06 = b5
    V05 = b4
    V04 = b3 ^ tmp
    V03 = b2 ^ tmp
    V02 = b1
    V01 = b0 ^ tmp
    V00 = tmp
    V00 = V00 ^ V40
    V01 = V01 ^ V41
    V02 = V02 ^ V42
    V03 = V03 ^ V43
    V04 = V04 ^ V44
    V05 = V05 ^ V45
    V06 = V06 ^ V46
    V07 = V07 ^ V47
    tmp = V47
    V47 = V46
    V46 = V45
    V45 = V44
    V44 = V43 ^ tmp
    V43 = V42 ^ tmp
    V42 = V41
    V41 = V40 ^ tmp
    V40 = tmp
    V40 = V40 ^ V30
    V41 = V41 ^ V31
    V42 = V42 ^ V32
    V43 = V43 ^ V33
    V44 = V44 ^ V34
    V45 = V45 ^ V35
    V46 = V46 ^ V36
    V47 = V47 ^ V37
    tmp = V37
    V37 = V36
    V36 = V35
    V35 = V34
    V34 = V33 ^ tmp
    V33 = V32 ^ tmp
    V32 = V31
    V31 = V30 ^ tmp
    V30 = tmp
    V30 = V30 ^ V20
    V31 = V31 ^ V21
    V32 = V32 ^ V22
    V33 = V33 ^ V23
    V34 = V34 ^ V24
    V35 = V35 ^ V25
    V36 = V36 ^ V26
    V37 = V37 ^ V27
    tmp = V27
    V27 = V26
    V26 = V25
    V25 = V24
    V24 = V23 ^ tmp
    V23 = V22 ^ tmp
    V22 = V21
    V21 = V20 ^ tmp
    V20 = tmp
    V20 = V20 ^ V10
    V21 = V21 ^ V11
    V22 = V22 ^ V12
    V23 = V23 ^ V13
    V24 = V24 ^ V14
    V25 = V25 ^ V15
    V26 = V26 ^ V16
    V27 = V27 ^ V17
    tmp = V17
    V17 = V16
    V16 = V15
    V15 = V14
    V14 = V13 ^ tmp
    V13 = V12 ^ tmp
    V12 = V11
    V11 = V10 ^ tmp
    V10 = tmp
    V10 = V10 ^ b0
    V11 = V11 ^ b1
    V12 = V12 ^ b2
    V13 = V13 ^ b3
    V14 = V14 ^ b4
    V15 = V15 ^ b5
    V16 = V16 ^ b6
    V17 = V17 ^ b7
    V00 = V00 ^ M0
    V01 = V01 ^ M1
    V02 = V02 ^ M2
    V03 = V03 ^ M3
    V04 = V04 ^ M4
    V05 = V05 ^ M5
    V06 = V06 ^ M6
    V07 = V07 ^ M7
    tmp = M7
    M7 = M6
    M6 = M5
    M5 = M4
    M4 = M3 ^ tmp
    M3 = M2 ^ tmp
    M2 = M1
    M1 = M0 ^ tmp
    M0 = tmp
    V10 = V10 ^ M0
    V11 = V11 ^ M1
    V12 = V12 ^ M2
    V13 = V13 ^ M3
    V14 = V14 ^ M4
    V15 = V15 ^ M5
    V16 = V16 ^ M6
    V17 = V17 ^ M7
    tmp = M7
    M7 = M6
    M6 = M5
    M5 = M4
    M4 = M3 ^ tmp
    M3 = M2 ^ tmp
    M2 = M1
    M1 = M0 ^ tmp
    M0 = tmp
    V20 = V20 ^ M0
    V21 = V21 ^ M1
    V22 = V22 ^ M2
    V23 = V23 ^ M3
    V24 = V24 ^ M4
    V25 = V25 ^ M5
    V26 = V26 ^ M6
    V27 = V27 ^ M7
    tmp = M7
    M7 = M6
    M6 = M5
    M5 = M4
    M4 = M3 ^ tmp
    M3 = M2 ^ tmp
    M2 = M1
    M1 = M0 ^ tmp
    M0 = tmp
    V30 = V30 ^ M0
    V31 = V31 ^ M1
    V32 = V32 ^ M2
    V33 = V33 ^ M3
    V34 = V34 ^ M4
    V35 = V35 ^ M5
    V36 = V36 ^ M6
    V37 = V37 ^ M7
    tmp = M7
    M7 = M6
    M6 = M5
    M5 = M4
    M4 = M3 ^ tmp
    M3 = M2 ^ tmp
    M2 = M1
    M1 = M0 ^ tmp
    M0 = tmp
    V40 = V40 ^ M0
    V41 = V41 ^ M1
    V42 = V42 ^ M2
    V43 = V43 ^ M3
    V44 = V44 ^ M4
    V45 = V45 ^ M5
    V46 = V46 ^ M6
    V47 = V47 ^ M7
    V14 = (V14 << 1) | (V14 >> 31)
    V15 = (V15 << 1) | (V15 >> 31)
    V16 = (V16 << 1) | (V16 >> 31)
    V17 = (V17 << 1) | (V17 >> 31)
    V24 = (V24 << 2) | (V24 >> 30)
    V25 = (V25 << 2) | (V25 >> 30)
    V26 = (V26 << 2) | (V26 >> 30)
    V27 = (V27 << 2) | (V27 >> 30)
    V34 = (V34 << 3) | (V34 >> 29)
    V35 = (V35 << 3) | (V35 >> 29)
    V36 = (V36 << 3) | (V36 >> 29)
    V37 = (V37 << 3) | (V37 >> 29)
    V44 = (V44 << 4) | (V44 >> 28)
    V45 = (V45 << 4) | (V45 >> 28)
    V46 = (V46 << 4) | (V46 >> 28)
    V47 = (V47 << 4) | (V47 >> 28)

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
        V00 ^= RC00_512[r]
        V04 ^= RC04_512[r]
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
        V10 ^= RC10_512[r]
        V14 ^= RC14_512[r]
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
        V20 ^= RC20_512[r]
        V24 ^= RC24_512[r]
    }

    for r := 0; r < 8; r++ {
        tmp = V30
        V30 |= V31
        V32 ^= V33
        V31 = ^V31
        V30 ^= V33
        V33 &= tmp
        V31 ^= V33
        V33 ^= V32
        V32 &= V30
        V30 = ^V30
        V32 ^= V31
        V31 |= V33
        tmp ^= V31
        V33 ^= V32
        V32 &= V31
        V31 ^= V30
        V30 = tmp
        tmp = V35
        V35 |= V36
        V37 ^= V34
        V36 = ^V36
        V35 ^= V34
        V34 &= tmp
        V36 ^= V34
        V34 ^= V37
        V37 &= V35
        V35 = ^V35
        V37 ^= V36
        V36 |= V34
        tmp ^= V36
        V34 ^= V37
        V37 &= V36
        V36 ^= V35
        V35 = tmp
        V34 ^= V30
        V30 = ((V30 << 2) | (V30 >> 30)) ^ V34
        V34 = ((V34 << 14) | (V34 >> 18)) ^ V30
        V30 = ((V30 << 10) | (V30 >> 22)) ^ V34
        V34 = (V34 << 1) | (V34 >> 31)
        V35 ^= V31
        V31 = ((V31 << 2) | (V31 >> 30)) ^ V35
        V35 = ((V35 << 14) | (V35 >> 18)) ^ V31
        V31 = ((V31 << 10) | (V31 >> 22)) ^ V35
        V35 = (V35 << 1) | (V35 >> 31)
        V36 ^= V32
        V32 = ((V32 << 2) | (V32 >> 30)) ^ V36
        V36 = ((V36 << 14) | (V36 >> 18)) ^ V32
        V32 = ((V32 << 10) | (V32 >> 22)) ^ V36
        V36 = (V36 << 1) | (V36 >> 31)
        V37 ^= V33
        V33 = ((V33 << 2) | (V33 >> 30)) ^ V37
        V37 = ((V37 << 14) | (V37 >> 18)) ^ V33
        V33 = ((V33 << 10) | (V33 >> 22)) ^ V37
        V37 = (V37 << 1) | (V37 >> 31)
        V30 ^= RC30_512[r]
        V34 ^= RC34_512[r]
    }

    for r := 0; r < 8; r++ {
        tmp = V40
        V40 |= V41
        V42 ^= V43
        V41 = ^V41
        V40 ^= V43
        V43 &= tmp
        V41 ^= V43
        V43 ^= V42
        V42 &= V40
        V40 = ^V40
        V42 ^= V41
        V41 |= V43
        tmp ^= V41
        V43 ^= V42
        V42 &= V41
        V41 ^= V40
        V40 = tmp
        tmp = V45
        V45 |= V46
        V47 ^= V44
        V46 = ^V46
        V45 ^= V44
        V44 &= tmp
        V46 ^= V44
        V44 ^= V47
        V47 &= V45
        V45 = ^V45
        V47 ^= V46
        V46 |= V44
        tmp ^= V46
        V44 ^= V47
        V47 &= V46
        V46 ^= V45
        V45 = tmp
        V44 ^= V40
        V40 = ((V40 << 2) | (V40 >> 30)) ^ V44
        V44 = ((V44 << 14) | (V44 >> 18)) ^ V40
        V40 = ((V40 << 10) | (V40 >> 22)) ^ V44
        V44 = (V44 << 1) | (V44 >> 31)
        V45 ^= V41
        V41 = ((V41 << 2) | (V41 >> 30)) ^ V45
        V45 = ((V45 << 14) | (V45 >> 18)) ^ V41
        V41 = ((V41 << 10) | (V41 >> 22)) ^ V45
        V45 = (V45 << 1) | (V45 >> 31)
        V46 ^= V42
        V42 = ((V42 << 2) | (V42 >> 30)) ^ V46
        V46 = ((V46 << 14) | (V46 >> 18)) ^ V42
        V42 = ((V42 << 10) | (V42 >> 22)) ^ V46
        V46 = (V46 << 1) | (V46 >> 31)
        V47 ^= V43
        V43 = ((V43 << 2) | (V43 >> 30)) ^ V47
        V47 = ((V47 << 14) | (V47 >> 18)) ^ V43
        V43 = ((V43 << 10) | (V43 >> 22)) ^ V47
        V47 = (V47 << 1) | (V47 >> 31)
        V40 ^= RC40_512[r]
        V44 ^= RC44_512[r]
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
    d.V30 = V30
    d.V31 = V31
    d.V32 = V32
    d.V33 = V33
    d.V34 = V34
    d.V35 = V35
    d.V36 = V36
    d.V37 = V37
    d.V40 = V40
    d.V41 = V41
    d.V42 = V42
    d.V43 = V43
    d.V44 = V44
    d.V45 = V45
    d.V46 = V46
    d.V47 = V47
}
