package vmac

import (
    "math/big"
)

func nh(k, m []byte) []byte {
    t := len(m) / 8
    y := big.NewInt(0)

    for i := 0; i < t; i += 2 {
        mi := bytesToBigint(m[i*8 : (i+1)*8])
        ki := bytesToBigint(k[i*8 : (i+1)*8])
        mj := bytesToBigint(m[(i+1)*8 : (i+2)*8])
        kj := bytesToBigint(k[(i+1)*8 : (i+2)*8])
        sumi := new(big.Int).Add(mi, ki)
        sumi.Mod(sumi, m64)
        sumj := new(big.Int).Add(mj, kj)
        sumj.Mod(sumj, m64)
        prod := new(big.Int).Mul(sumi, sumj)
        prod.Mod(prod, m128)
        y.Add(y, prod)
        y.Mod(y, m128)
    }
    y.Mod(y, m126)

    Y := make([]byte, 16)
    copy(Y[16-len(y.Bytes()):], y.Bytes())
    return Y
}

func bytesToBigint(b []byte) *big.Int {
    return new(big.Int).SetBytes(b)
}

// Zero pad s to a multiple of 16 bytes
func zeroPad(s []byte) []byte {
    r := len(s) % 16
    if r != 0 {
        t := make([]byte, len(s)+16-r)
        copy(t, s)
        s = t
    }
    return s
}

func endianSwap(s []byte) []byte {
    t := make([]byte, len(s))
    for i := 0; i < len(s); i += 8 {
        t[i] = s[i+7]
        t[i+1] = s[i+6]
        t[i+2] = s[i+5]
        t[i+3] = s[i+4]
        t[i+4] = s[i+3]
        t[i+5] = s[i+2]
        t[i+6] = s[i+1]
        t[i+7] = s[i]
    }

    return t
}
