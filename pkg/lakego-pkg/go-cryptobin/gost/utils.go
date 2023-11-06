package gost

import (
    "math/big"
)

func Reverse(d []byte) {
    for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
        d[i], d[j] = d[j], d[i]
    }
}

func BytesToBigint(d []byte) *big.Int {
    return big.NewInt(0).SetBytes(d)
}

func BytesPadding(d []byte, size int) []byte {
    return append(make([]byte, size-len(d)), d...)
}

func pointSize(p *big.Int) int {
    if p.BitLen() > 256 {
        return 64
    }

    return 32
}
