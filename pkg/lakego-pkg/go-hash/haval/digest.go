package haval

import (
    "errors"
)

const (
    // hash size
    Size128 = 16
    Size160 = 20
    Size192 = 24
    Size224 = 28
    Size256 = 32

    BlockSize = 128
)

// digest represents the partial evaluation of a checksum.
type digest struct {
    s   [8]uint32
    x   [BlockSize]byte
    nx  int
    len uint64

    /**
     * Output length, in 32-bit words (4, 5, 6, 7 or 8).
     */
    olen uint32

    /**
     * Number of passes (3, 4 or 5).
     */
    passes uint32

    padBuf [10]byte
    s0, s1, s2, s3, s4, s5, s6, s7 uint32
    inw [32]uint32
}

// newDigest returns a new hash.Hash computing the haval checksum
func newDigest(outputLength uint32, passes uint32) (*digest, error) {
    d := new(digest)
    d.olen = outputLength >> 5
    d.passes = passes

    switch d.olen {
        case 4, 5, 6, 7, 8:
            break
        default:
            return nil, errors.New("go-hash/haval: invalid outputLength size")
    }

    switch d.passes {
        case 3, 4, 5:
            break
        default:
            return nil, errors.New("go-hash/haval: invalid passes size")
    }

    d.Reset()

    return d, nil
}

func (d *digest) Reset() {
    d.s = [8]uint32{}
    d.x = [BlockSize]byte{}

    d.nx = 0
    d.len = 0

    d.padBuf = [10]byte{}
    d.inw = [32]uint32{}

    d.s0 = iv[0]
    d.s1 = iv[1]
    d.s2 = iv[2]
    d.s3 = iv[3]
    d.s4 = iv[4]
    d.s5 = iv[5]
    d.s6 = iv[6]
    d.s7 = iv[7]
}

func (d *digest) Size() int {
    return int(d.olen) * 4
}

func (d *digest) BlockSize() int {
    return BlockSize
}

func (d *digest) Write(p []byte) (nn int, err error) {
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

func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *digest) checkSum() []byte {
    dataLen := d.nx

    var currentLength uint64 = (((d.len/BlockSize) << 7) + uint64(dataLen)) << 3

    d.padBuf[0] = byte(0x01 | byte(d.passes << 3))
    d.padBuf[1] = byte(d.olen << 3)

    putu32(d.padBuf[2:], uint32(currentLength))
    putu32(d.padBuf[6:], uint32(currentLength >> 32))

    var endLen uint32 = uint32((dataLen + 138) & ^127)
    d.Write([]byte{0x01})

    var i uint32
    for i = uint32(dataLen) + 1; i < (endLen - 10); i++ {
        d.Write([]byte{0x00})
    }

    d.Write(d.padBuf[:])

    return d.writeOutput()
}

func (d *digest) processBlock(data []byte) {
    for i := 0; i < 32; i++ {
        d.inw[i] = getu32(data[4 * i:])
    }

    var save0 = d.s0
    var save1 = d.s1
    var save2 = d.s2
    var save3 = d.s3
    var save4 = d.s4
    var save5 = d.s5
    var save6 = d.s6
    var save7 = d.s7

    switch d.passes {
        case 3:
            d.pass31(d.inw[:])
            d.pass32(d.inw[:])
            d.pass33(d.inw[:])
        case 4:
            d.pass41(d.inw[:])
            d.pass42(d.inw[:])
            d.pass43(d.inw[:])
            d.pass44(d.inw[:])
        case 5:
            d.pass51(d.inw[:])
            d.pass52(d.inw[:])
            d.pass53(d.inw[:])
            d.pass54(d.inw[:])
            d.pass55(d.inw[:])
    }

    d.s0 += save0
    d.s1 += save1
    d.s2 += save2
    d.s3 += save3
    d.s4 += save4
    d.s5 += save5
    d.s6 += save6
    d.s7 += save7
}

func (d *digest) pass31(inw []uint32) {
    x0 := d.s0
    x1 := d.s1
    x2 := d.s2
    x3 := d.s3
    x4 := d.s4
    x5 := d.s5
    x6 := d.s6
    x7 := d.s7

    for i := 0; i < 32; i += 8 {
        x7 = circularLeft(F1(x1, x0, x3, x5, x6, x2, x4), 25) + circularLeft(x7, 21) + inw[i + 0]
        x6 = circularLeft(F1(x0, x7, x2, x4, x5, x1, x3), 25) + circularLeft(x6, 21) + inw[i + 1]
        x5 = circularLeft(F1(x7, x6, x1, x3, x4, x0, x2), 25) + circularLeft(x5, 21) + inw[i + 2]
        x4 = circularLeft(F1(x6, x5, x0, x2, x3, x7, x1), 25) + circularLeft(x4, 21) + inw[i + 3]
        x3 = circularLeft(F1(x5, x4, x7, x1, x2, x6, x0), 25) + circularLeft(x3, 21) + inw[i + 4]
        x2 = circularLeft(F1(x4, x3, x6, x0, x1, x5, x7), 25) + circularLeft(x2, 21) + inw[i + 5]
        x1 = circularLeft(F1(x3, x2, x5, x7, x0, x4, x6), 25) + circularLeft(x1, 21) + inw[i + 6]
        x0 = circularLeft(F1(x2, x1, x4, x6, x7, x3, x5), 25) + circularLeft(x0, 21) + inw[i + 7]
    }

    d.s0 = x0; d.s1 = x1; d.s2 = x2; d.s3 = x3
    d.s4 = x4; d.s5 = x5; d.s6 = x6; d.s7 = x7
}

func (d *digest) pass32(inw []uint32) {
    x0 := d.s0
    x1 := d.s1
    x2 := d.s2
    x3 := d.s3
    x4 := d.s4
    x5 := d.s5
    x6 := d.s6
    x7 := d.s7

    for i := 0; i < 32; i += 8 {
        x7 = circularLeft(F2(x4, x2, x1, x0, x5, x3, x6), 25) + circularLeft(x7, 21) + inw[wp2[i + 0]] + K2[i + 0]
        x6 = circularLeft(F2(x3, x1, x0, x7, x4, x2, x5), 25) + circularLeft(x6, 21) + inw[wp2[i + 1]] + K2[i + 1]
        x5 = circularLeft(F2(x2, x0, x7, x6, x3, x1, x4), 25) + circularLeft(x5, 21) + inw[wp2[i + 2]] + K2[i + 2]
        x4 = circularLeft(F2(x1, x7, x6, x5, x2, x0, x3), 25) + circularLeft(x4, 21) + inw[wp2[i + 3]] + K2[i + 3]
        x3 = circularLeft(F2(x0, x6, x5, x4, x1, x7, x2), 25) + circularLeft(x3, 21) + inw[wp2[i + 4]] + K2[i + 4]
        x2 = circularLeft(F2(x7, x5, x4, x3, x0, x6, x1), 25) + circularLeft(x2, 21) + inw[wp2[i + 5]] + K2[i + 5]
        x1 = circularLeft(F2(x6, x4, x3, x2, x7, x5, x0), 25) + circularLeft(x1, 21) + inw[wp2[i + 6]] + K2[i + 6]
        x0 = circularLeft(F2(x5, x3, x2, x1, x6, x4, x7), 25) + circularLeft(x0, 21) + inw[wp2[i + 7]] + K2[i + 7]
    }

    d.s0 = x0; d.s1 = x1; d.s2 = x2; d.s3 = x3
    d.s4 = x4; d.s5 = x5; d.s6 = x6; d.s7 = x7
}

func (d *digest) pass33(inw []uint32) {
    x0 := d.s0
    x1 := d.s1
    x2 := d.s2
    x3 := d.s3
    x4 := d.s4
    x5 := d.s5
    x6 := d.s6
    x7 := d.s7

    for i := 0; i < 32; i += 8 {
        x7 = circularLeft(F3(x6, x1, x2, x3, x4, x5, x0), 25) + circularLeft(x7, 21) + inw[wp3[i + 0]] + K3[i + 0]
        x6 = circularLeft(F3(x5, x0, x1, x2, x3, x4, x7), 25) + circularLeft(x6, 21) + inw[wp3[i + 1]] + K3[i + 1]
        x5 = circularLeft(F3(x4, x7, x0, x1, x2, x3, x6), 25) + circularLeft(x5, 21) + inw[wp3[i + 2]] + K3[i + 2]
        x4 = circularLeft(F3(x3, x6, x7, x0, x1, x2, x5), 25) + circularLeft(x4, 21) + inw[wp3[i + 3]] + K3[i + 3]
        x3 = circularLeft(F3(x2, x5, x6, x7, x0, x1, x4), 25) + circularLeft(x3, 21) + inw[wp3[i + 4]] + K3[i + 4]
        x2 = circularLeft(F3(x1, x4, x5, x6, x7, x0, x3), 25) + circularLeft(x2, 21) + inw[wp3[i + 5]] + K3[i + 5]
        x1 = circularLeft(F3(x0, x3, x4, x5, x6, x7, x2), 25) + circularLeft(x1, 21) + inw[wp3[i + 6]] + K3[i + 6]
        x0 = circularLeft(F3(x7, x2, x3, x4, x5, x6, x1), 25) + circularLeft(x0, 21) + inw[wp3[i + 7]] + K3[i + 7]
    }

    d.s0 = x0; d.s1 = x1; d.s2 = x2; d.s3 = x3
    d.s4 = x4; d.s5 = x5; d.s6 = x6; d.s7 = x7
}

func (d *digest) pass41(inw []uint32) {
    x0 := d.s0
    x1 := d.s1
    x2 := d.s2
    x3 := d.s3
    x4 := d.s4
    x5 := d.s5
    x6 := d.s6
    x7 := d.s7

    for i := 0; i < 32; i += 8 {
        x7 = circularLeft(F1(x2, x6, x1, x4, x5, x3, x0), 25) + circularLeft(x7, 21) + inw[i + 0]
        x6 = circularLeft(F1(x1, x5, x0, x3, x4, x2, x7), 25) + circularLeft(x6, 21) + inw[i + 1]
        x5 = circularLeft(F1(x0, x4, x7, x2, x3, x1, x6), 25) + circularLeft(x5, 21) + inw[i + 2]
        x4 = circularLeft(F1(x7, x3, x6, x1, x2, x0, x5), 25) + circularLeft(x4, 21) + inw[i + 3]
        x3 = circularLeft(F1(x6, x2, x5, x0, x1, x7, x4), 25) + circularLeft(x3, 21) + inw[i + 4]
        x2 = circularLeft(F1(x5, x1, x4, x7, x0, x6, x3), 25) + circularLeft(x2, 21) + inw[i + 5]
        x1 = circularLeft(F1(x4, x0, x3, x6, x7, x5, x2), 25) + circularLeft(x1, 21) + inw[i + 6]
        x0 = circularLeft(F1(x3, x7, x2, x5, x6, x4, x1), 25) + circularLeft(x0, 21) + inw[i + 7]
    }

    d.s0 = x0; d.s1 = x1; d.s2 = x2; d.s3 = x3
    d.s4 = x4; d.s5 = x5; d.s6 = x6; d.s7 = x7
}

func (d *digest) pass42(inw []uint32) {
    x0 := d.s0
    x1 := d.s1
    x2 := d.s2
    x3 := d.s3
    x4 := d.s4
    x5 := d.s5
    x6 := d.s6
    x7 := d.s7

    for i := 0; i < 32; i += 8 {
        x7 = circularLeft(F2(x3, x5, x2, x0, x1, x6, x4), 25) + circularLeft(x7, 21) + inw[wp2[i + 0]] + K2[i + 0]
        x6 = circularLeft(F2(x2, x4, x1, x7, x0, x5, x3), 25) + circularLeft(x6, 21) + inw[wp2[i + 1]] + K2[i + 1]
        x5 = circularLeft(F2(x1, x3, x0, x6, x7, x4, x2), 25) + circularLeft(x5, 21) + inw[wp2[i + 2]] + K2[i + 2]
        x4 = circularLeft(F2(x0, x2, x7, x5, x6, x3, x1), 25) + circularLeft(x4, 21) + inw[wp2[i + 3]] + K2[i + 3]
        x3 = circularLeft(F2(x7, x1, x6, x4, x5, x2, x0), 25) + circularLeft(x3, 21) + inw[wp2[i + 4]] + K2[i + 4]
        x2 = circularLeft(F2(x6, x0, x5, x3, x4, x1, x7), 25) + circularLeft(x2, 21) + inw[wp2[i + 5]] + K2[i + 5]
        x1 = circularLeft(F2(x5, x7, x4, x2, x3, x0, x6), 25) + circularLeft(x1, 21) + inw[wp2[i + 6]] + K2[i + 6]
        x0 = circularLeft(F2(x4, x6, x3, x1, x2, x7, x5), 25) + circularLeft(x0, 21) + inw[wp2[i + 7]] + K2[i + 7]
    }

    d.s0 = x0; d.s1 = x1; d.s2 = x2; d.s3 = x3
    d.s4 = x4; d.s5 = x5; d.s6 = x6; d.s7 = x7
}

func (d *digest) pass43(inw []uint32) {
    x0 := d.s0
    x1 := d.s1
    x2 := d.s2
    x3 := d.s3
    x4 := d.s4
    x5 := d.s5
    x6 := d.s6
    x7 := d.s7

    for i := 0; i < 32; i += 8 {
        x7 = circularLeft(F3(x1, x4, x3, x6, x0, x2, x5), 25) + circularLeft(x7, 21) + inw[wp3[i + 0]] + K3[i + 0]
        x6 = circularLeft(F3(x0, x3, x2, x5, x7, x1, x4), 25) + circularLeft(x6, 21) + inw[wp3[i + 1]] + K3[i + 1]
        x5 = circularLeft(F3(x7, x2, x1, x4, x6, x0, x3), 25) + circularLeft(x5, 21) + inw[wp3[i + 2]] + K3[i + 2]
        x4 = circularLeft(F3(x6, x1, x0, x3, x5, x7, x2), 25) + circularLeft(x4, 21) + inw[wp3[i + 3]] + K3[i + 3]
        x3 = circularLeft(F3(x5, x0, x7, x2, x4, x6, x1), 25) + circularLeft(x3, 21) + inw[wp3[i + 4]] + K3[i + 4]
        x2 = circularLeft(F3(x4, x7, x6, x1, x3, x5, x0), 25) + circularLeft(x2, 21) + inw[wp3[i + 5]] + K3[i + 5]
        x1 = circularLeft(F3(x3, x6, x5, x0, x2, x4, x7), 25) + circularLeft(x1, 21) + inw[wp3[i + 6]] + K3[i + 6]
        x0 = circularLeft(F3(x2, x5, x4, x7, x1, x3, x6), 25) + circularLeft(x0, 21) + inw[wp3[i + 7]] + K3[i + 7]
    }

    d.s0 = x0; d.s1 = x1; d.s2 = x2; d.s3 = x3
    d.s4 = x4; d.s5 = x5; d.s6 = x6; d.s7 = x7
}

func (d *digest) pass44(inw []uint32) {
    x0 := d.s0
    x1 := d.s1
    x2 := d.s2
    x3 := d.s3
    x4 := d.s4
    x5 := d.s5
    x6 := d.s6
    x7 := d.s7

    for i := 0; i < 32; i += 8 {
        x7 = circularLeft(F4(x6, x4, x0, x5, x2, x1, x3), 25) + circularLeft(x7, 21) + inw[wp4[i + 0]] + K4[i + 0]
        x6 = circularLeft(F4(x5, x3, x7, x4, x1, x0, x2), 25) + circularLeft(x6, 21) + inw[wp4[i + 1]] + K4[i + 1]
        x5 = circularLeft(F4(x4, x2, x6, x3, x0, x7, x1), 25) + circularLeft(x5, 21) + inw[wp4[i + 2]] + K4[i + 2]
        x4 = circularLeft(F4(x3, x1, x5, x2, x7, x6, x0), 25) + circularLeft(x4, 21) + inw[wp4[i + 3]] + K4[i + 3]
        x3 = circularLeft(F4(x2, x0, x4, x1, x6, x5, x7), 25) + circularLeft(x3, 21) + inw[wp4[i + 4]] + K4[i + 4]
        x2 = circularLeft(F4(x1, x7, x3, x0, x5, x4, x6), 25) + circularLeft(x2, 21) + inw[wp4[i + 5]] + K4[i + 5]
        x1 = circularLeft(F4(x0, x6, x2, x7, x4, x3, x5), 25) + circularLeft(x1, 21) + inw[wp4[i + 6]] + K4[i + 6]
        x0 = circularLeft(F4(x7, x5, x1, x6, x3, x2, x4), 25) + circularLeft(x0, 21) + inw[wp4[i + 7]] + K4[i + 7]
    }

    d.s0 = x0; d.s1 = x1; d.s2 = x2; d.s3 = x3
    d.s4 = x4; d.s5 = x5; d.s6 = x6; d.s7 = x7
}

func (d *digest) pass51(inw []uint32) {
    x0 := d.s0
    x1 := d.s1
    x2 := d.s2
    x3 := d.s3
    x4 := d.s4
    x5 := d.s5
    x6 := d.s6
    x7 := d.s7

    for i := 0; i < 32; i += 8 {
        x7 = circularLeft(F1(x3, x4, x1, x0, x5, x2, x6), 25) + circularLeft(x7, 21) + inw[i + 0]
        x6 = circularLeft(F1(x2, x3, x0, x7, x4, x1, x5), 25) + circularLeft(x6, 21) + inw[i + 1]
        x5 = circularLeft(F1(x1, x2, x7, x6, x3, x0, x4), 25) + circularLeft(x5, 21) + inw[i + 2]
        x4 = circularLeft(F1(x0, x1, x6, x5, x2, x7, x3), 25) + circularLeft(x4, 21) + inw[i + 3]
        x3 = circularLeft(F1(x7, x0, x5, x4, x1, x6, x2), 25) + circularLeft(x3, 21) + inw[i + 4]
        x2 = circularLeft(F1(x6, x7, x4, x3, x0, x5, x1), 25) + circularLeft(x2, 21) + inw[i + 5]
        x1 = circularLeft(F1(x5, x6, x3, x2, x7, x4, x0), 25) + circularLeft(x1, 21) + inw[i + 6]
        x0 = circularLeft(F1(x4, x5, x2, x1, x6, x3, x7), 25) + circularLeft(x0, 21) + inw[i + 7]
    }

    d.s0 = x0; d.s1 = x1; d.s2 = x2; d.s3 = x3
    d.s4 = x4; d.s5 = x5; d.s6 = x6; d.s7 = x7
}

func (d *digest) pass52(inw []uint32) {
    x0 := d.s0
    x1 := d.s1
    x2 := d.s2
    x3 := d.s3
    x4 := d.s4
    x5 := d.s5
    x6 := d.s6
    x7 := d.s7

    for i := 0; i < 32; i += 8 {
        x7 = circularLeft(F2(x6, x2, x1, x0, x3, x4, x5), 25) + circularLeft(x7, 21) + inw[wp2[i + 0]] + K2[i + 0]
        x6 = circularLeft(F2(x5, x1, x0, x7, x2, x3, x4), 25) + circularLeft(x6, 21) + inw[wp2[i + 1]] + K2[i + 1]
        x5 = circularLeft(F2(x4, x0, x7, x6, x1, x2, x3), 25) + circularLeft(x5, 21) + inw[wp2[i + 2]] + K2[i + 2]
        x4 = circularLeft(F2(x3, x7, x6, x5, x0, x1, x2), 25) + circularLeft(x4, 21) + inw[wp2[i + 3]] + K2[i + 3]
        x3 = circularLeft(F2(x2, x6, x5, x4, x7, x0, x1), 25) + circularLeft(x3, 21) + inw[wp2[i + 4]] + K2[i + 4]
        x2 = circularLeft(F2(x1, x5, x4, x3, x6, x7, x0), 25) + circularLeft(x2, 21) + inw[wp2[i + 5]] + K2[i + 5]
        x1 = circularLeft(F2(x0, x4, x3, x2, x5, x6, x7), 25) + circularLeft(x1, 21) + inw[wp2[i + 6]] + K2[i + 6]
        x0 = circularLeft(F2(x7, x3, x2, x1, x4, x5, x6), 25) + circularLeft(x0, 21) + inw[wp2[i + 7]] + K2[i + 7]
    }

    d.s0 = x0; d.s1 = x1; d.s2 = x2; d.s3 = x3
    d.s4 = x4; d.s5 = x5; d.s6 = x6; d.s7 = x7
}

func (d *digest) pass53(inw []uint32) {
    x0 := d.s0
    x1 := d.s1
    x2 := d.s2
    x3 := d.s3
    x4 := d.s4
    x5 := d.s5
    x6 := d.s6
    x7 := d.s7

    for i := 0; i < 32; i += 8 {
        x7 = circularLeft(F3(x2, x6, x0, x4, x3, x1, x5), 25) + circularLeft(x7, 21) + inw[wp3[i + 0]] + K3[i + 0]
        x6 = circularLeft(F3(x1, x5, x7, x3, x2, x0, x4), 25) + circularLeft(x6, 21) + inw[wp3[i + 1]] + K3[i + 1]
        x5 = circularLeft(F3(x0, x4, x6, x2, x1, x7, x3), 25) + circularLeft(x5, 21) + inw[wp3[i + 2]] + K3[i + 2]
        x4 = circularLeft(F3(x7, x3, x5, x1, x0, x6, x2), 25) + circularLeft(x4, 21) + inw[wp3[i + 3]] + K3[i + 3]
        x3 = circularLeft(F3(x6, x2, x4, x0, x7, x5, x1), 25) + circularLeft(x3, 21) + inw[wp3[i + 4]] + K3[i + 4]
        x2 = circularLeft(F3(x5, x1, x3, x7, x6, x4, x0), 25) + circularLeft(x2, 21) + inw[wp3[i + 5]] + K3[i + 5]
        x1 = circularLeft(F3(x4, x0, x2, x6, x5, x3, x7), 25) + circularLeft(x1, 21) + inw[wp3[i + 6]] + K3[i + 6]
        x0 = circularLeft(F3(x3, x7, x1, x5, x4, x2, x6), 25) + circularLeft(x0, 21) + inw[wp3[i + 7]] + K3[i + 7]
    }

    d.s0 = x0; d.s1 = x1; d.s2 = x2; d.s3 = x3
    d.s4 = x4; d.s5 = x5; d.s6 = x6; d.s7 = x7
}

func (d *digest) pass54(inw []uint32) {
    x0 := d.s0
    x1 := d.s1
    x2 := d.s2
    x3 := d.s3
    x4 := d.s4
    x5 := d.s5
    x6 := d.s6
    x7 := d.s7

    for i := 0; i < 32; i += 8 {
        x7 = circularLeft(F4(x1, x5, x3, x2, x0, x4, x6), 25) + circularLeft(x7, 21) + inw[wp4[i + 0]] + K4[i + 0]
        x6 = circularLeft(F4(x0, x4, x2, x1, x7, x3, x5), 25) + circularLeft(x6, 21) + inw[wp4[i + 1]] + K4[i + 1]
        x5 = circularLeft(F4(x7, x3, x1, x0, x6, x2, x4), 25) + circularLeft(x5, 21) + inw[wp4[i + 2]] + K4[i + 2]
        x4 = circularLeft(F4(x6, x2, x0, x7, x5, x1, x3), 25) + circularLeft(x4, 21) + inw[wp4[i + 3]] + K4[i + 3]
        x3 = circularLeft(F4(x5, x1, x7, x6, x4, x0, x2), 25) + circularLeft(x3, 21) + inw[wp4[i + 4]] + K4[i + 4]
        x2 = circularLeft(F4(x4, x0, x6, x5, x3, x7, x1), 25) + circularLeft(x2, 21) + inw[wp4[i + 5]] + K4[i + 5]
        x1 = circularLeft(F4(x3, x7, x5, x4, x2, x6, x0), 25) + circularLeft(x1, 21) + inw[wp4[i + 6]] + K4[i + 6]
        x0 = circularLeft(F4(x2, x6, x4, x3, x1, x5, x7), 25) + circularLeft(x0, 21) + inw[wp4[i + 7]] + K4[i + 7]
    }

    d.s0 = x0; d.s1 = x1; d.s2 = x2; d.s3 = x3
    d.s4 = x4; d.s5 = x5; d.s6 = x6; d.s7 = x7
}

func (d *digest) pass55(inw []uint32) {
    x0 := d.s0
    x1 := d.s1
    x2 := d.s2
    x3 := d.s3
    x4 := d.s4
    x5 := d.s5
    x6 := d.s6
    x7 := d.s7

    for i := 0; i < 32; i += 8 {
        x7 = circularLeft(F5(x2, x5, x0, x6, x4, x3, x1), 25) + circularLeft(x7, 21) + inw[wp5[i + 0]] + K5[i + 0]
        x6 = circularLeft(F5(x1, x4, x7, x5, x3, x2, x0), 25) + circularLeft(x6, 21) + inw[wp5[i + 1]] + K5[i + 1]
        x5 = circularLeft(F5(x0, x3, x6, x4, x2, x1, x7), 25) + circularLeft(x5, 21) + inw[wp5[i + 2]] + K5[i + 2]
        x4 = circularLeft(F5(x7, x2, x5, x3, x1, x0, x6), 25) + circularLeft(x4, 21) + inw[wp5[i + 3]] + K5[i + 3]
        x3 = circularLeft(F5(x6, x1, x4, x2, x0, x7, x5), 25) + circularLeft(x3, 21) + inw[wp5[i + 4]] + K5[i + 4]
        x2 = circularLeft(F5(x5, x0, x3, x1, x7, x6, x4), 25) + circularLeft(x2, 21) + inw[wp5[i + 5]] + K5[i + 5]
        x1 = circularLeft(F5(x4, x7, x2, x0, x6, x5, x3), 25) + circularLeft(x1, 21) + inw[wp5[i + 6]] + K5[i + 6]
        x0 = circularLeft(F5(x3, x6, x1, x7, x5, x4, x2), 25) + circularLeft(x0, 21) + inw[wp5[i + 7]] + K5[i + 7]
    }

    d.s0 = x0; d.s1 = x1; d.s2 = x2; d.s3 = x3
    d.s4 = x4; d.s5 = x5; d.s6 = x6; d.s7 = x7
}

func (d *digest) write128() (out []byte) {
    out = make([]byte, 16)

    s0 := d.s0; s1 := d.s1; s2 := d.s2; s3 := d.s3
    s4 := d.s4; s5 := d.s5; s6 := d.s6; s7 := d.s7

    putu32(out[0:], s0 + mix128(s7, s4, s5, s6, 24))
    putu32(out[4:], s1 + mix128(s6, s7, s4, s5, 16))
    putu32(out[8:], s2 + mix128(s5, s6, s7, s4,  8))
    putu32(out[12:], s3 + mix128(s4, s5, s6, s7,  0))

    return
}

func (d *digest) write160() (out []byte) {
    out = make([]byte, 20)

    s0 := d.s0; s1 := d.s1; s2 := d.s2; s3 := d.s3
    s4 := d.s4; s5 := d.s5; s6 := d.s6; s7 := d.s7

    putu32(out[0:], s0 + mix160_0(s5, s6, s7))
    putu32(out[4:], s1 + mix160_1(s5, s6, s7))
    putu32(out[8:], s2 + mix160_2(s5, s6, s7))
    putu32(out[12:], s3 + mix160_3(s5, s6, s7))
    putu32(out[16:], s4 + mix160_4(s5, s6, s7))

    return
}

func (d *digest) write192() (out []byte) {
    out = make([]byte, 24)

    s0 := d.s0; s1 := d.s1; s2 := d.s2; s3 := d.s3
    s4 := d.s4; s5 := d.s5; s6 := d.s6; s7 := d.s7

    putu32(out[0:], s0 + mix192_0(s6, s7))
    putu32(out[4:], s1 + mix192_1(s6, s7))
    putu32(out[8:], s2 + mix192_2(s6, s7))
    putu32(out[12:], s3 + mix192_3(s6, s7))
    putu32(out[16:], s4 + mix192_4(s6, s7))
    putu32(out[20:], s5 + mix192_5(s6, s7))

    return
}

func (d *digest) write224() (out []byte) {
    out = make([]byte, 28)

    s0 := d.s0; s1 := d.s1; s2 := d.s2; s3 := d.s3
    s4 := d.s4; s5 := d.s5; s6 := d.s6; s7 := d.s7

    putu32(out[0:], s0 + ((s7 >> 27) & 0x1F))
    putu32(out[4:], s1 + ((s7 >> 22) & 0x1F))
    putu32(out[8:], s2 + ((s7 >> 18) & 0x0F))
    putu32(out[12:], s3 + ((s7 >> 13) & 0x1F))
    putu32(out[16:], s4 + ((s7 >>  9) & 0x0F))
    putu32(out[20:], s5 + ((s7 >>  4) & 0x1F))
    putu32(out[24:], s6 + ((s7       ) & 0x0F))

    return
}

func (d *digest) write256() (out []byte) {
    out = make([]byte, 32)

    s0 := d.s0; s1 := d.s1; s2 := d.s2; s3 := d.s3
    s4 := d.s4; s5 := d.s5; s6 := d.s6; s7 := d.s7

    putu32(out[0:], s0)
    putu32(out[4:], s1)
    putu32(out[8:], s2)
    putu32(out[12:], s3)
    putu32(out[16:], s4)
    putu32(out[20:], s5)
    putu32(out[24:], s6)
    putu32(out[28:], s7)

    return
}

func (d *digest) writeOutput() (out []byte) {
    switch d.olen {
        case 4:
            return d.write128()
        case 5:
            return d.write160()
        case 6:
            return d.write192()
        case 7:
            return d.write224()
        case 8:
            return d.write256()
    }

    return nil
}
