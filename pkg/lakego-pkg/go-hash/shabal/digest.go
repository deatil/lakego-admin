package shabal

import (
    "fmt"
    "errors"
)

const (
    // hash size
    Size192 = 24
    Size224 = 28
    Size256 = 32
    Size384 = 48
    Size512 = 64

    BlockSize = 64
)

// digest represents the partial evaluation of a checksum.
type digest struct {
    s   [44]uint32
    x   [BlockSize]byte
    nx  int
    len uint64

    outSizeW32 int

    buf   [64]byte
    ptr   int
    state [44]uint32
    W     int64
}

// newDigest returns a new *digest computing the shabal checksum
func newDigest(outSize int) (*digest, error) {
    if outSize < 32 || outSize > 512 || (outSize & 31) != 0 {
        return nil, errors.New(fmt.Sprintf("go-hash/shabal: invalid Shabal output size: %d", outSize))
    }

    d := new(digest)
    d.outSizeW32 = outSize >> 5
    d.Reset()

    return d, nil
}

func (d *digest) Reset() {
    d.s = [44]uint32{}
    d.x = [BlockSize]byte{}
    d.nx = 0
    d.len = 0

    d.buf = [64]byte{}
    d.ptr = 0
    d.W = 1

    switch d.outSizeW32 {
        case 6:
            d.state = iv192
        case 7:
            d.state = iv224
        case 8:
            d.state = iv256
        case 12:
            d.state = iv384
        case 16:
            d.state = iv512
        default:
            d.state = d.getIV(d.outSizeW32)
    }
}

func (d *digest) Size() int {
    return d.outSizeW32 << 2
}

func (d *digest) BlockSize() int {
    return BlockSize
}

func (d *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    d.len += uint64(nn)

    plen := len(p)
    off := 0
    if d.ptr != 0 {
        var rlen = 64 - d.ptr
        if plen < rlen {
            copy(d.buf[d.ptr:], p[:plen])
            d.ptr += plen
            return
        } else {
            copy(d.buf[d.ptr:], p[:rlen])
            off += rlen
            plen -= rlen
            d.core(d.buf[:], 1)
        }
    }

    var num = plen >> 6
    if num > 0 {
        d.core(p[off:], num)
        off += num << 6
        plen &= 63
    }

    copy(d.buf[:], p[off:])
    d.ptr = plen

    return
}

func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *digest) checkSum() (out []byte) {
    var dlen = d.Size()

    d.buf[d.ptr] = 0x80
    d.ptr++

    for i := d.ptr; i < 64; i++ {
        d.buf[i] = 0
    }

    for i := 0; i < 4; i++ {
        d.core(d.buf[:], 1)
        d.W--
    }

    out = make([]byte, dlen)

    var j = 44 - (dlen >> 2)
    var w uint32 = 0
    for i := 0; i < dlen; i++ {
        if (i & 3) == 0 {
            w = d.state[j]
            j++
        }

        out[i] = byte(w)
        w >>= 8
    }

    return
}

func (d *digest) getIV(outSizeW32 int) [44]uint32 {
    var outSize = outSizeW32 << 5

    sg := new(digest)
    sg.buf = [64]byte{}
    sg.state = [44]uint32{}

    for i := 0; i < 44; i++ {
        sg.state[i] = 0;
    }

    sg.W = int64(-1)
    for i := 0; i < 16; i++ {
        sg.buf[(i << 2) + 0] = byte(outSize + i);
        sg.buf[(i << 2) + 1] = byte((outSize + i) >> 8)
    }

    sg.core(sg.buf[:], 1)
    for i := 0; i < 16; i++ {
        sg.buf[(i << 2) + 0] = byte(outSize + i + 16)
        sg.buf[(i << 2) + 1] = byte((outSize + i + 16) >> 8)
    }

    sg.core(sg.buf[:], 1)

    return sg.state
}

func (d *digest) core(data []byte, num int) {
    state := &d.state

    var A0 = state[ 0];
    var A1 = state[ 1];
    var A2 = state[ 2];
    var A3 = state[ 3];
    var A4 = state[ 4];
    var A5 = state[ 5];
    var A6 = state[ 6];
    var A7 = state[ 7];
    var A8 = state[ 8];
    var A9 = state[ 9];
    var AA = state[10];
    var AB = state[11];

    var B0 = state[12];
    var B1 = state[13];
    var B2 = state[14];
    var B3 = state[15];
    var B4 = state[16];
    var B5 = state[17];
    var B6 = state[18];
    var B7 = state[19];
    var B8 = state[20];
    var B9 = state[21];
    var BA = state[22];
    var BB = state[23];
    var BC = state[24];
    var BD = state[25];
    var BE = state[26];
    var BF = state[27];

    var C0 = state[28];
    var C1 = state[29];
    var C2 = state[30];
    var C3 = state[31];
    var C4 = state[32];
    var C5 = state[33];
    var C6 = state[34];
    var C7 = state[35];
    var C8 = state[36];
    var C9 = state[37];
    var CA = state[38];
    var CB = state[39];
    var CC = state[40];
    var CD = state[41];
    var CE = state[42];
    var CF = state[43];

    off := 0
    for num > 0 {
        var M0 = getu32(data[off +  0:]);
        B0 += M0;
        B0 = (B0 << 17) | (B0 >> 15);
        var M1 = getu32(data[off +  4:]);
        B1 += M1;
        B1 = (B1 << 17) | (B1 >> 15);
        var M2 = getu32(data[off +  8:]);
        B2 += M2;
        B2 = (B2 << 17) | (B2 >> 15);
        var M3 = getu32(data[off + 12:]);
        B3 += M3;
        B3 = (B3 << 17) | (B3 >> 15);
        var M4 = getu32(data[off + 16:]);
        B4 += M4;
        B4 = (B4 << 17) | (B4 >> 15);
        var M5 = getu32(data[off + 20:]);
        B5 += M5;
        B5 = (B5 << 17) | (B5 >> 15);
        var M6 = getu32(data[off + 24:]);
        B6 += M6;
        B6 = (B6 << 17) | (B6 >> 15);
        var M7 = getu32(data[off + 28:]);
        B7 += M7;
        B7 = (B7 << 17) | (B7 >> 15);
        var M8 = getu32(data[off + 32:]);
        B8 += M8;
        B8 = (B8 << 17) | (B8 >> 15);
        var M9 = getu32(data[off + 36:]);
        B9 += M9;
        B9 = (B9 << 17) | (B9 >> 15);
        var MA = getu32(data[off + 40:]);
        BA += MA;
        BA = (BA << 17) | (BA >> 15);
        var MB = getu32(data[off + 44:]);
        BB += MB;
        BB = (BB << 17) | (BB >> 15);
        var MC = getu32(data[off + 48:]);
        BC += MC;
        BC = (BC << 17) | (BC >> 15);
        var MD = getu32(data[off + 52:]);
        BD += MD;
        BD = (BD << 17) | (BD >> 15);
        var ME = getu32(data[off + 56:]);
        BE += ME;
        BE = (BE << 17) | (BE >> 15);
        var MF = getu32(data[off + 60:]);
        BF += MF;
        BF = (BF << 17) | (BF >> 15);

        off += 64;
        A0 ^= uint32(d.W)
        A1 ^= uint32(d.W >> 32)
        d.W++

        A0 = ((A0 ^ (((AB << 15) | (AB >> 17)) * 5) ^ C8) * 3) ^ BD ^ (B9 & ^B6) ^ M0;
        B0 = ^((B0 << 1) | (B0 >> 31)) ^ A0;
        A1 = ((A1 ^ (((A0 << 15) | (A0 >> 17)) * 5) ^ C7) * 3) ^ BE ^ (BA & ^B7) ^ M1;
        B1 = ^((B1 << 1) | (B1 >> 31)) ^ A1;
        A2 = ((A2 ^ (((A1 << 15) | (A1 >> 17)) * 5) ^ C6) * 3) ^ BF ^ (BB & ^B8) ^ M2;
        B2 = ^((B2 << 1) | (B2 >> 31)) ^ A2;
        A3 = ((A3 ^ (((A2 << 15) | (A2 >> 17)) * 5) ^ C5) * 3) ^ B0 ^ (BC & ^B9) ^ M3;
        B3 = ^((B3 << 1) | (B3 >> 31)) ^ A3;
        A4 = ((A4 ^ (((A3 << 15) | (A3 >> 17)) * 5) ^ C4) * 3) ^ B1 ^ (BD & ^BA) ^ M4;
        B4 = ^((B4 << 1) | (B4 >> 31)) ^ A4;
        A5 = ((A5 ^ (((A4 << 15) | (A4 >> 17)) * 5) ^ C3) * 3) ^ B2 ^ (BE & ^BB) ^ M5;
        B5 = ^((B5 << 1) | (B5 >> 31)) ^ A5;
        A6 = ((A6 ^ (((A5 << 15) | (A5 >> 17)) * 5) ^ C2) * 3) ^ B3 ^ (BF & ^BC) ^ M6;
        B6 = ^((B6 << 1) | (B6 >> 31)) ^ A6;
        A7 = ((A7 ^ (((A6 << 15) | (A6 >> 17)) * 5) ^ C1) * 3) ^ B4 ^ (B0 & ^BD) ^ M7;
        B7 = ^((B7 << 1) | (B7 >> 31)) ^ A7;
        A8 = ((A8 ^ (((A7 << 15) | (A7 >> 17)) * 5) ^ C0) * 3) ^ B5 ^ (B1 & ^BE) ^ M8;
        B8 = ^((B8 << 1) | (B8 >> 31)) ^ A8;
        A9 = ((A9 ^ (((A8 << 15) | (A8 >> 17)) * 5) ^ CF) * 3) ^ B6 ^ (B2 & ^BF) ^ M9;
        B9 = ^((B9 << 1) | (B9 >> 31)) ^ A9;
        AA = ((AA ^ (((A9 << 15) | (A9 >> 17)) * 5) ^ CE) * 3) ^ B7 ^ (B3 & ^B0) ^ MA;
        BA = ^((BA << 1) | (BA >> 31)) ^ AA;
        AB = ((AB ^ (((AA << 15) | (AA >> 17)) * 5) ^ CD) * 3) ^ B8 ^ (B4 & ^B1) ^ MB;
        BB = ^((BB << 1) | (BB >> 31)) ^ AB;
        A0 = ((A0 ^ (((AB << 15) | (AB >> 17)) * 5) ^ CC) * 3) ^ B9 ^ (B5 & ^B2) ^ MC;
        BC = ^((BC << 1) | (BC >> 31)) ^ A0;
        A1 = ((A1 ^ (((A0 << 15) | (A0 >> 17)) * 5) ^ CB) * 3) ^ BA ^ (B6 & ^B3) ^ MD;
        BD = ^((BD << 1) | (BD >> 31)) ^ A1;
        A2 = ((A2 ^ (((A1 << 15) | (A1 >> 17)) * 5) ^ CA) * 3) ^ BB ^ (B7 & ^B4) ^ ME;
        BE = ^((BE << 1) | (BE >> 31)) ^ A2;
        A3 = ((A3 ^ (((A2 << 15) | (A2 >> 17)) * 5) ^ C9) * 3) ^ BC ^ (B8 & ^B5) ^ MF;
        BF = ^((BF << 1) | (BF >> 31)) ^ A3;
        A4 = ((A4 ^ (((A3 << 15) | (A3 >> 17)) * 5) ^ C8) * 3) ^ BD ^ (B9 & ^B6) ^ M0;
        B0 = ^((B0 << 1) | (B0 >> 31)) ^ A4;
        A5 = ((A5 ^ (((A4 << 15) | (A4 >> 17)) * 5) ^ C7) * 3) ^ BE ^ (BA & ^B7) ^ M1;
        B1 = ^((B1 << 1) | (B1 >> 31)) ^ A5;
        A6 = ((A6 ^ (((A5 << 15) | (A5 >> 17)) * 5) ^ C6) * 3) ^ BF ^ (BB & ^B8) ^ M2;
        B2 = ^((B2 << 1) | (B2 >> 31)) ^ A6;
        A7 = ((A7 ^ (((A6 << 15) | (A6 >> 17)) * 5) ^ C5) * 3) ^ B0 ^ (BC & ^B9) ^ M3;
        B3 = ^((B3 << 1) | (B3 >> 31)) ^ A7;
        A8 = ((A8 ^ (((A7 << 15) | (A7 >> 17)) * 5) ^ C4) * 3) ^ B1 ^ (BD & ^BA) ^ M4;
        B4 = ^((B4 << 1) | (B4 >> 31)) ^ A8;
        A9 = ((A9 ^ (((A8 << 15) | (A8 >> 17)) * 5) ^ C3) * 3) ^ B2 ^ (BE & ^BB) ^ M5;
        B5 = ^((B5 << 1) | (B5 >> 31)) ^ A9;
        AA = ((AA ^ (((A9 << 15) | (A9 >> 17)) * 5) ^ C2) * 3) ^ B3 ^ (BF & ^BC) ^ M6;
        B6 = ^((B6 << 1) | (B6 >> 31)) ^ AA;
        AB = ((AB ^ (((AA << 15) | (AA >> 17)) * 5) ^ C1) * 3) ^ B4 ^ (B0 & ^BD) ^ M7;
        B7 = ^((B7 << 1) | (B7 >> 31)) ^ AB;
        A0 = ((A0 ^ (((AB << 15) | (AB >> 17)) * 5) ^ C0) * 3) ^ B5 ^ (B1 & ^BE) ^ M8;
        B8 = ^((B8 << 1) | (B8 >> 31)) ^ A0;
        A1 = ((A1 ^ (((A0 << 15) | (A0 >> 17)) * 5) ^ CF) * 3) ^ B6 ^ (B2 & ^BF) ^ M9;
        B9 = ^((B9 << 1) | (B9 >> 31)) ^ A1;
        A2 = ((A2 ^ (((A1 << 15) | (A1 >> 17)) * 5) ^ CE) * 3) ^ B7 ^ (B3 & ^B0) ^ MA;
        BA = ^((BA << 1) | (BA >> 31)) ^ A2;
        A3 = ((A3 ^ (((A2 << 15) | (A2 >> 17)) * 5) ^ CD) * 3) ^ B8 ^ (B4 & ^B1) ^ MB;
        BB = ^((BB << 1) | (BB >> 31)) ^ A3;
        A4 = ((A4 ^ (((A3 << 15) | (A3 >> 17)) * 5) ^ CC) * 3) ^ B9 ^ (B5 & ^B2) ^ MC;
        BC = ^((BC << 1) | (BC >> 31)) ^ A4;
        A5 = ((A5 ^ (((A4 << 15) | (A4 >> 17)) * 5) ^ CB) * 3) ^ BA ^ (B6 & ^B3) ^ MD;
        BD = ^((BD << 1) | (BD >> 31)) ^ A5;
        A6 = ((A6 ^ (((A5 << 15) | (A5 >> 17)) * 5) ^ CA) * 3) ^ BB ^ (B7 & ^B4) ^ ME;
        BE = ^((BE << 1) | (BE >> 31)) ^ A6;
        A7 = ((A7 ^ (((A6 << 15) | (A6 >> 17)) * 5) ^ C9) * 3) ^ BC ^ (B8 & ^B5) ^ MF;
        BF = ^((BF << 1) | (BF >> 31)) ^ A7;
        A8 = ((A8 ^ (((A7 << 15) | (A7 >> 17)) * 5) ^ C8) * 3) ^ BD ^ (B9 & ^B6) ^ M0;
        B0 = ^((B0 << 1) | (B0 >> 31)) ^ A8;
        A9 = ((A9 ^ (((A8 << 15) | (A8 >> 17)) * 5) ^ C7) * 3) ^ BE ^ (BA & ^B7) ^ M1;
        B1 = ^((B1 << 1) | (B1 >> 31)) ^ A9;
        AA = ((AA ^ (((A9 << 15) | (A9 >> 17)) * 5) ^ C6) * 3) ^ BF ^ (BB & ^B8) ^ M2;
        B2 = ^((B2 << 1) | (B2 >> 31)) ^ AA;
        AB = ((AB ^ (((AA << 15) | (AA >> 17)) * 5) ^ C5) * 3) ^ B0 ^ (BC & ^B9) ^ M3;
        B3 = ^((B3 << 1) | (B3 >> 31)) ^ AB;
        A0 = ((A0 ^ (((AB << 15) | (AB >> 17)) * 5) ^ C4) * 3) ^ B1 ^ (BD & ^BA) ^ M4;
        B4 = ^((B4 << 1) | (B4 >> 31)) ^ A0;
        A1 = ((A1 ^ (((A0 << 15) | (A0 >> 17)) * 5) ^ C3) * 3) ^ B2 ^ (BE & ^BB) ^ M5;
        B5 = ^((B5 << 1) | (B5 >> 31)) ^ A1;
        A2 = ((A2 ^ (((A1 << 15) | (A1 >> 17)) * 5) ^ C2) * 3) ^ B3 ^ (BF & ^BC) ^ M6;
        B6 = ^((B6 << 1) | (B6 >> 31)) ^ A2;
        A3 = ((A3 ^ (((A2 << 15) | (A2 >> 17)) * 5) ^ C1) * 3) ^ B4 ^ (B0 & ^BD) ^ M7;
        B7 = ^((B7 << 1) | (B7 >> 31)) ^ A3;
        A4 = ((A4 ^ (((A3 << 15) | (A3 >> 17)) * 5) ^ C0) * 3) ^ B5 ^ (B1 & ^BE) ^ M8;
        B8 = ^((B8 << 1) | (B8 >> 31)) ^ A4;
        A5 = ((A5 ^ (((A4 << 15) | (A4 >> 17)) * 5) ^ CF) * 3) ^ B6 ^ (B2 & ^BF) ^ M9;
        B9 = ^((B9 << 1) | (B9 >> 31)) ^ A5;
        A6 = ((A6 ^ (((A5 << 15) | (A5 >> 17)) * 5) ^ CE) * 3) ^ B7 ^ (B3 & ^B0) ^ MA;
        BA = ^((BA << 1) | (BA >> 31)) ^ A6;
        A7 = ((A7 ^ (((A6 << 15) | (A6 >> 17)) * 5) ^ CD) * 3) ^ B8 ^ (B4 & ^B1) ^ MB;
        BB = ^((BB << 1) | (BB >> 31)) ^ A7;
        A8 = ((A8 ^ (((A7 << 15) | (A7 >> 17)) * 5) ^ CC) * 3) ^ B9 ^ (B5 & ^B2) ^ MC;
        BC = ^((BC << 1) | (BC >> 31)) ^ A8;
        A9 = ((A9 ^ (((A8 << 15) | (A8 >> 17)) * 5) ^ CB) * 3) ^ BA ^ (B6 & ^B3) ^ MD;
        BD = ^((BD << 1) | (BD >> 31)) ^ A9;
        AA = ((AA ^ (((A9 << 15) | (A9 >> 17)) * 5) ^ CA) * 3) ^ BB ^ (B7 & ^B4) ^ ME;
        BE = ^((BE << 1) | (BE >> 31)) ^ AA;
        AB = ((AB ^ (((AA << 15) | (AA >> 17)) * 5) ^ C9) * 3) ^ BC ^ (B8 & ^B5) ^ MF;
        BF = ^((BF << 1) | (BF >> 31)) ^ AB;

        AB += C6 + CA + CE;
        AA += C5 + C9 + CD;
        A9 += C4 + C8 + CC;
        A8 += C3 + C7 + CB;
        A7 += C2 + C6 + CA;
        A6 += C1 + C5 + C9;
        A5 += C0 + C4 + C8;
        A4 += CF + C3 + C7;
        A3 += CE + C2 + C6;
        A2 += CD + C1 + C5;
        A1 += CC + C0 + C4;
        A0 += CB + CF + C3;

        var tmp uint32
        tmp = B0; B0 = C0 - M0; C0 = tmp;
        tmp = B1; B1 = C1 - M1; C1 = tmp;
        tmp = B2; B2 = C2 - M2; C2 = tmp;
        tmp = B3; B3 = C3 - M3; C3 = tmp;
        tmp = B4; B4 = C4 - M4; C4 = tmp;
        tmp = B5; B5 = C5 - M5; C5 = tmp;
        tmp = B6; B6 = C6 - M6; C6 = tmp;
        tmp = B7; B7 = C7 - M7; C7 = tmp;
        tmp = B8; B8 = C8 - M8; C8 = tmp;
        tmp = B9; B9 = C9 - M9; C9 = tmp;
        tmp = BA; BA = CA - MA; CA = tmp;
        tmp = BB; BB = CB - MB; CB = tmp;
        tmp = BC; BC = CC - MC; CC = tmp;
        tmp = BD; BD = CD - MD; CD = tmp;
        tmp = BE; BE = CE - ME; CE = tmp;
        tmp = BF; BF = CF - MF; CF = tmp;

        num--
    }

    state[ 0] = A0;
    state[ 1] = A1;
    state[ 2] = A2;
    state[ 3] = A3;
    state[ 4] = A4;
    state[ 5] = A5;
    state[ 6] = A6;
    state[ 7] = A7;
    state[ 8] = A8;
    state[ 9] = A9;
    state[10] = AA;
    state[11] = AB;

    state[12] = B0;
    state[13] = B1;
    state[14] = B2;
    state[15] = B3;
    state[16] = B4;
    state[17] = B5;
    state[18] = B6;
    state[19] = B7;
    state[20] = B8;
    state[21] = B9;
    state[22] = BA;
    state[23] = BB;
    state[24] = BC;
    state[25] = BD;
    state[26] = BE;
    state[27] = BF;

    state[28] = C0;
    state[29] = C1;
    state[30] = C2;
    state[31] = C3;
    state[32] = C4;
    state[33] = C5;
    state[34] = C6;
    state[35] = C7;
    state[36] = C8;
    state[37] = C9;
    state[38] = CA;
    state[39] = CB;
    state[40] = CC;
    state[41] = CD;
    state[42] = CE;
    state[43] = CF;
}
