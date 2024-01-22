package p256

import (
    "bytes"
    "math/big"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/gm/sm2/field"
)

func UnmarshalCompressed(curve elliptic.Curve, a []byte) (x, y *big.Int) {
    var aa, xx, xx3 field.Element

    c, ok := curve.(sm2Curve)
    if !ok {
        return
    }

    x = new(big.Int).SetBytes(a[1:])

    xx.FromBig(x)
    xx3.Square(&xx)    // x3 = x ^ 2
    xx3.Mul(&xx3, &xx) // x3 = x ^ 2 * x
    aa.Mul(&c.a, &xx)  // a = a * x
    xx3.Add(&xx3, &aa)
    xx3.Add(&xx3, &c.b)

    y2 := xx3.ToBig()
    y = new(big.Int).ModSqrt(y2, c.P)

    if getLastBit(y) != uint(a[0]) {
        y.Sub(c.P, y)
    }

    return
}

func MarshalCompressed(x, y *big.Int) []byte {
    buf := []byte{}

    yp := getLastBit(y)

    buf = append(buf, x.Bytes()...)

    buf = zeroPadding(buf, 32)
    buf = append([]byte{byte(yp)}, buf...)

    return buf
}

func getLastBit(a *big.Int) uint {
    return 2 | a.Bit(0)
}

// zero padding
func zeroPadding(text []byte, size int) []byte {
    if size < 1 {
        return text
    }

    n := len(text)

    if n == size {
        return text
    }

    if n < size {
        r := bytes.Repeat([]byte("0"), size - n)
        return append(r, text...)
    }

    return text[n-size:]
}
