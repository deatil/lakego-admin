package gost

import (
    "math/big"
)

// Reverse bytes
func Reverse(b []byte) []byte {
    d := make([]byte, len(b))
    copy(d, b)

    for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
        d[i], d[j] = d[j], d[i]
    }

    return d
}

func bigIntFromBytes(b []byte) *big.Int {
    return new(big.Int).SetBytes(b)
}
