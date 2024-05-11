package radio_gatun

const (
    // hash size
    Size64 = 32

    BlockSize64 = 312
)

// digest312 represents the partial evaluation of a checksum.
type digest64 struct {
    s   [39]uint64
    x   [BlockSize64]byte
    nx  int
    len uint64

    a [19]uint64
    b [39]uint64
}

// newDigest64 returns a new *digest64 computing the radio_gatun checksum
func newDigest64() *digest64 {
    d := new(digest64)
    d.Reset()

    return d
}

func (d *digest64) Reset() {
    d.s = [39]uint64{}
    d.x = [BlockSize64]byte{}

    d.nx = 0
    d.len = 0

    d.a = [19]uint64{}
    d.b = [39]uint64{}
}

func (d *digest64) Size() int {
    return Size32
}

func (d *digest64) BlockSize() int {
    return BlockSize64
}

func (d *digest64) Write(p []byte) (nn int, err error) {
    nn = len(p)

    d.len += uint64(nn)

    plen := len(p)

    for d.nx + plen >= BlockSize64 {
        copy(d.x[d.nx:], p)

        d.processBlock(d.x[:])

        xx := BlockSize64 - d.nx
        plen -= xx

        p = p[xx:]
        d.nx = 0
    }

    copy(d.x[d.nx:], p)
    d.nx += plen

    return
}

func (d *digest64) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *digest64) checkSum() (out []byte) {
    ptr := d.nx

    d.x[ptr] = 0x01
    ptr++

    for i := ptr; i < 312; i++ {
        d.x[i] = 0
    }

    d.processBlock(d.x[:])

    var num = 18
    for {
        ptr += 24
        if ptr > 312 {
            break
        }
        num--
    }

    return d.blank(num)
}

func (d *digest64) processBlock(data []byte) {
    var a00 = d.a[ 0];
    var a01 = d.a[ 1];
    var a02 = d.a[ 2];
    var a03 = d.a[ 3];
    var a04 = d.a[ 4];
    var a05 = d.a[ 5];
    var a06 = d.a[ 6];
    var a07 = d.a[ 7];
    var a08 = d.a[ 8];
    var a09 = d.a[ 9];
    var a10 = d.a[10];
    var a11 = d.a[11];
    var a12 = d.a[12];
    var a13 = d.a[13];
    var a14 = d.a[14];
    var a15 = d.a[15];
    var a16 = d.a[16];
    var a17 = d.a[17];
    var a18 = d.a[18];

    dp := 0
    for mk := 12; mk >= 0; mk-- {
        var p0 = getu64(data[dp + 0:]);
        var p1 = getu64(data[dp + 8:]);
        var p2 = getu64(data[dp + 16:]);

        dp += 24;

        var bj int
        if mk == 12 {
            bj = 0
        } else {
            bj = 3 * (mk + 1)
        }

        d.b[bj + 0] ^= p0;
        d.b[bj + 1] ^= p1;
        d.b[bj + 2] ^= p2;
        a16 ^= p0;
        a17 ^= p1;
        a18 ^= p2;

        bj = mk * 3;

        bj += 3
        if bj == 39 {
            bj = 0;
        }
        d.b[bj + 0] ^= a01;

        bj += 3
        if bj == 39 {
            bj = 0;
        }
        d.b[bj + 1] ^= a02;

        bj += 3
        if bj == 39 {
            bj = 0;
        }
        d.b[bj + 2] ^= a03;

        bj += 3
        if bj == 39 {
            bj = 0;
        }
        d.b[bj + 0] ^= a04;

        bj += 3
        if bj == 39 {
            bj = 0;
        }
        d.b[bj + 1] ^= a05;

        bj += 3
        if bj == 39 {
            bj = 0;
        }
        d.b[bj + 2] ^= a06;

        bj += 3
        if bj == 39 {
            bj = 0;
        }
        d.b[bj + 0] ^= a07;

        bj += 3
        if bj == 39 {
            bj = 0;
        }
        d.b[bj + 1] ^= a08;

        bj += 3
        if bj == 39 {
            bj = 0;
        }
        d.b[bj + 2] ^= a09;

        bj += 3
        if bj == 39 {
            bj = 0;
        }
        d.b[bj + 0] ^= a10;

        bj += 3
        if bj == 39 {
            bj = 0;
        }
        d.b[bj + 1] ^= a11;

        bj += 3
        if bj == 39 {
            bj = 0;
        }
        d.b[bj + 2] ^= a12;

        var t00 = a00 ^ (a01 | ^a02);
        var t01 = a01 ^ (a02 | ^a03);
        var t02 = a02 ^ (a03 | ^a04);
        var t03 = a03 ^ (a04 | ^a05);
        var t04 = a04 ^ (a05 | ^a06);
        var t05 = a05 ^ (a06 | ^a07);
        var t06 = a06 ^ (a07 | ^a08);
        var t07 = a07 ^ (a08 | ^a09);
        var t08 = a08 ^ (a09 | ^a10);
        var t09 = a09 ^ (a10 | ^a11);
        var t10 = a10 ^ (a11 | ^a12);
        var t11 = a11 ^ (a12 | ^a13);
        var t12 = a12 ^ (a13 | ^a14);
        var t13 = a13 ^ (a14 | ^a15);
        var t14 = a14 ^ (a15 | ^a16);
        var t15 = a15 ^ (a16 | ^a17);
        var t16 = a16 ^ (a17 | ^a18);
        var t17 = a17 ^ (a18 | ^a00);
        var t18 = a18 ^ (a00 | ^a01);

        a00 = t00;
        a01 = (t07 << 63) | (t07 >>  1);
        a02 = (t14 << 61) | (t14 >>  3);
        a03 = (t02 << 58) | (t02 >>  6);
        a04 = (t09 << 54) | (t09 >> 10);
        a05 = (t16 << 49) | (t16 >> 15);
        a06 = (t04 << 43) | (t04 >> 21);
        a07 = (t11 << 36) | (t11 >> 28);
        a08 = (t18 << 28) | (t18 >> 36);
        a09 = (t06 << 19) | (t06 >> 45);
        a10 = (t13 <<  9) | (t13 >> 55);
        a11 = (t01 << 62) | (t01 >>  2);
        a12 = (t08 << 50) | (t08 >> 14);
        a13 = (t15 << 37) | (t15 >> 27);
        a14 = (t03 << 23) | (t03 >> 41);
        a15 = (t10 <<  8) | (t10 >> 56);
        a16 = (t17 << 56) | (t17 >>  8);
        a17 = (t05 << 39) | (t05 >> 25);
        a18 = (t12 << 21) | (t12 >> 43);

        t00 = a00 ^ a01 ^ a04;
        t01 = a01 ^ a02 ^ a05;
        t02 = a02 ^ a03 ^ a06;
        t03 = a03 ^ a04 ^ a07;
        t04 = a04 ^ a05 ^ a08;
        t05 = a05 ^ a06 ^ a09;
        t06 = a06 ^ a07 ^ a10;
        t07 = a07 ^ a08 ^ a11;
        t08 = a08 ^ a09 ^ a12;
        t09 = a09 ^ a10 ^ a13;
        t10 = a10 ^ a11 ^ a14;
        t11 = a11 ^ a12 ^ a15;
        t12 = a12 ^ a13 ^ a16;
        t13 = a13 ^ a14 ^ a17;
        t14 = a14 ^ a15 ^ a18;
        t15 = a15 ^ a16 ^ a00;
        t16 = a16 ^ a17 ^ a01;
        t17 = a17 ^ a18 ^ a02;
        t18 = a18 ^ a00 ^ a03;

        a00 = t00 ^ 1;
        a01 = t01;
        a02 = t02;
        a03 = t03;
        a04 = t04;
        a05 = t05;
        a06 = t06;
        a07 = t07;
        a08 = t08;
        a09 = t09;
        a10 = t10;
        a11 = t11;
        a12 = t12;
        a13 = t13;
        a14 = t14;
        a15 = t15;
        a16 = t16;
        a17 = t17;
        a18 = t18;

        bj = mk * 3;
        a13 ^= d.b[bj + 0];
        a14 ^= d.b[bj + 1];
        a15 ^= d.b[bj + 2];
    }

    d.a[ 0] = a00;
    d.a[ 1] = a01;
    d.a[ 2] = a02;
    d.a[ 3] = a03;
    d.a[ 4] = a04;
    d.a[ 5] = a05;
    d.a[ 6] = a06;
    d.a[ 7] = a07;
    d.a[ 8] = a08;
    d.a[ 9] = a09;
    d.a[10] = a10;
    d.a[11] = a11;
    d.a[12] = a12;
    d.a[13] = a13;
    d.a[14] = a14;
    d.a[15] = a15;
    d.a[16] = a16;
    d.a[17] = a17;
    d.a[18] = a18;
}

func (d *digest64) blank(num int) (out []byte) {
    var a00 = d.a[ 0];
    var a01 = d.a[ 1];
    var a02 = d.a[ 2];
    var a03 = d.a[ 3];
    var a04 = d.a[ 4];
    var a05 = d.a[ 5];
    var a06 = d.a[ 6];
    var a07 = d.a[ 7];
    var a08 = d.a[ 8];
    var a09 = d.a[ 9];
    var a10 = d.a[10];
    var a11 = d.a[11];
    var a12 = d.a[12];
    var a13 = d.a[13];
    var a14 = d.a[14];
    var a15 = d.a[15];
    var a16 = d.a[16];
    var a17 = d.a[17];
    var a18 = d.a[18];

    out = make([]byte, Size64)

    off := 0
    for num > 0 {
        d.b[ 0] ^= a01;
        d.b[ 4] ^= a02;
        d.b[ 8] ^= a03;
        d.b[ 9] ^= a04;
        d.b[13] ^= a05;
        d.b[17] ^= a06;
        d.b[18] ^= a07;
        d.b[22] ^= a08;
        d.b[26] ^= a09;
        d.b[27] ^= a10;
        d.b[31] ^= a11;
        d.b[35] ^= a12;

        var t00 = a00 ^ (a01 | ^a02);
        var t01 = a01 ^ (a02 | ^a03);
        var t02 = a02 ^ (a03 | ^a04);
        var t03 = a03 ^ (a04 | ^a05);
        var t04 = a04 ^ (a05 | ^a06);
        var t05 = a05 ^ (a06 | ^a07);
        var t06 = a06 ^ (a07 | ^a08);
        var t07 = a07 ^ (a08 | ^a09);
        var t08 = a08 ^ (a09 | ^a10);
        var t09 = a09 ^ (a10 | ^a11);
        var t10 = a10 ^ (a11 | ^a12);
        var t11 = a11 ^ (a12 | ^a13);
        var t12 = a12 ^ (a13 | ^a14);
        var t13 = a13 ^ (a14 | ^a15);
        var t14 = a14 ^ (a15 | ^a16);
        var t15 = a15 ^ (a16 | ^a17);
        var t16 = a16 ^ (a17 | ^a18);
        var t17 = a17 ^ (a18 | ^a00);
        var t18 = a18 ^ (a00 | ^a01);

        a00 = t00;
        a01 = (t07 << 63) | (t07 >>  1);
        a02 = (t14 << 61) | (t14 >>  3);
        a03 = (t02 << 58) | (t02 >>  6);
        a04 = (t09 << 54) | (t09 >> 10);
        a05 = (t16 << 49) | (t16 >> 15);
        a06 = (t04 << 43) | (t04 >> 21);
        a07 = (t11 << 36) | (t11 >> 28);
        a08 = (t18 << 28) | (t18 >> 36);
        a09 = (t06 << 19) | (t06 >> 45);
        a10 = (t13 <<  9) | (t13 >> 55);
        a11 = (t01 << 62) | (t01 >>  2);
        a12 = (t08 << 50) | (t08 >> 14);
        a13 = (t15 << 37) | (t15 >> 27);
        a14 = (t03 << 23) | (t03 >> 41);
        a15 = (t10 <<  8) | (t10 >> 56);
        a16 = (t17 << 56) | (t17 >>  8);
        a17 = (t05 << 39) | (t05 >> 25);
        a18 = (t12 << 21) | (t12 >> 43);

        t00 = a00 ^ a01 ^ a04;
        t01 = a01 ^ a02 ^ a05;
        t02 = a02 ^ a03 ^ a06;
        t03 = a03 ^ a04 ^ a07;
        t04 = a04 ^ a05 ^ a08;
        t05 = a05 ^ a06 ^ a09;
        t06 = a06 ^ a07 ^ a10;
        t07 = a07 ^ a08 ^ a11;
        t08 = a08 ^ a09 ^ a12;
        t09 = a09 ^ a10 ^ a13;
        t10 = a10 ^ a11 ^ a14;
        t11 = a11 ^ a12 ^ a15;
        t12 = a12 ^ a13 ^ a16;
        t13 = a13 ^ a14 ^ a17;
        t14 = a14 ^ a15 ^ a18;
        t15 = a15 ^ a16 ^ a00;
        t16 = a16 ^ a17 ^ a01;
        t17 = a17 ^ a18 ^ a02;
        t18 = a18 ^ a00 ^ a03;

        a00 = t00 ^ 1;
        a01 = t01;
        a02 = t02;
        a03 = t03;
        a04 = t04;
        a05 = t05;
        a06 = t06;
        a07 = t07;
        a08 = t08;
        a09 = t09;
        a10 = t10;
        a11 = t11;
        a12 = t12;
        a13 = t13;
        a14 = t14;
        a15 = t15;
        a16 = t16;
        a17 = t17;
        a18 = t18;

        var bt0 = d.b[36];
        var bt1 = d.b[37];
        var bt2 = d.b[38];

        a13 ^= bt0;
        a14 ^= bt1;
        a15 ^= bt2;

        copy(d.b[3:], d.b[0:36])

        d.b[0] = bt0;
        d.b[1] = bt1;
        d.b[2] = bt2;

        if num <= 2 {
            putu64(out[off + 0:], a01)
            putu64(out[off + 8:], a02)

            off += 16;
        }

        num--
    }

    return
}

