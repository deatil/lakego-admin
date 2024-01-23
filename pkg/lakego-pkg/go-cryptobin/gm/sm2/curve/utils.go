package curve

import (
    "bytes"
    "math/big"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/gm/sm2/field"
)

func UnmarshalCompressed(curve elliptic.Curve, d []byte) (x, y *big.Int) {
    var a, b, aa, xx, xx3 field.Element

    params := curve.Params()

    a1 := new(big.Int).Sub(params.P, big.NewInt(3))

    a.FromBig(a1)
    b.FromBig(params.B)

    x = new(big.Int).SetBytes(d[1:])

    xx.FromBig(x)
    xx3.Square(&xx)    // x3 = x ^ 2
    xx3.Mul(&xx3, &xx) // x3 = x ^ 2 * x
    aa.Mul(&a, &xx)    // a = a * x
    xx3.Add(&xx3, &aa)
    xx3.Add(&xx3, &b)

    y2 := xx3.ToBig()
    y = new(big.Int).ModSqrt(y2, params.P)

    if getLastBit(y) != uint(d[0]) {
        y.Sub(params.P, y)
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

func bigFromDecimal(s string) *big.Int {
    b, ok := new(big.Int).SetString(s, 10)
    if !ok {
        panic("cryptobin/sm2: internal error: invalid encoding")
    }

    return b
}

func bigFromHex(s string) *big.Int {
    b, ok := new(big.Int).SetString(s, 16)
    if !ok {
        panic("cryptobin/sm2: internal error: invalid encoding")
    }

    return b
}
