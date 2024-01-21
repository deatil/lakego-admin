package p256

import (
    "bytes"
    "math/big"

    "github.com/deatil/go-cryptobin/gm/sm2/field"
)

func UnmarshalCompressed(curve P256Curve, a []byte) (x, y *big.Int) {
    var aa, xx, xx3 field.Element

    x = new(big.Int).SetBytes(a[1:])

    xx.FromBig(x)
    xx3.Square(&xx)       // x3 = x ^ 2
    xx3.Mul(&xx3, &xx)    // x3 = x ^ 2 * x
    aa.Mul(&curve.A, &xx) // a = a * x
    xx3.Add(&xx3, &aa)
    xx3.Add(&xx3, &curve.b)

    y2 := xx3.ToBig()
    y = new(big.Int).ModSqrt(y2, curve.P)

    if getLastBit(y) != uint(a[0]) {
        y.Sub(curve.P, y)
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

func getScalar(b *[32]byte, a []byte) {
    var scalarBytes []byte

    n := new(big.Int).SetBytes(a)
    if n.Cmp(sm2P256.N) >= 0 {
        n.Mod(n, sm2P256.N)
        scalarBytes = n.Bytes()
    } else {
        scalarBytes = a
    }

    for i, v := range scalarBytes {
        b[len(scalarBytes)-(1+i)] = v
    }
}

func WNafReversed(wnaf []int8) []int8 {
    wnafRev := make([]int8, len(wnaf))

    for i, v := range wnaf {
        wnafRev[len(wnaf)-(1+i)] = v
    }

    return wnafRev
}

func genrateWNaf(b []byte) []int8 {
    n:= new(big.Int).SetBytes(b)

    var k *big.Int
    if n.Cmp(sm2P256.N) >= 0 {
        n.Mod(n, sm2P256.N)
        k = n
    } else {
        k = n
    }

    wnaf := make([]int8, k.BitLen()+1, k.BitLen()+1)
    if k.Sign() == 0 {
        return wnaf
    }

    var width, pow2, sign int
    width, pow2, sign = 4, 16, 8

    var mask int64 = 15
    var carry bool
    var length, pos int

    for pos <= k.BitLen() {
        if k.Bit(pos) == boolToUint(carry) {
            pos++
            continue
        }

        k.Rsh(k, uint(pos))

        var digit int
        digit = int(k.Int64() & mask)
        if carry {
            digit++
        }

        carry = (digit & sign) != 0
        if carry {
            digit -= pow2
        }

        length += pos
        wnaf[length] = int8(digit)

        pos = int(width)
    }

    if len(wnaf) > length + 1 {
        t := make([]int8, length+1, length+1)
        copy(t, wnaf[0:length+1])
        wnaf = t
    }

    return wnaf
}

func boolToUint(b bool) uint {
    if b {
        return 1
    }
    return 0
}

func zForAffine(x, y *big.Int) *big.Int {
    z := new(big.Int)
    if x.Sign() != 0 || y.Sign() != 0 {
        z.SetInt64(1)
    }

    return z
}
