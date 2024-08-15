package sm2

import (
    "math/big"
    "crypto/subtle"
    "crypto/elliptic"
    "encoding/binary"
)

func intToBytes(x int) []byte {
    var buf = make([]byte, 4)
    binary.BigEndian.PutUint32(buf, uint32(x))

    return buf
}

func bigIntToBytes(curve elliptic.Curve, value *big.Int) []byte {
    byteLen := (curve.Params().BitSize + 7) / 8

    buf := make([]byte, byteLen)
    value.FillBytes(buf)

    return buf
}

func bytesToBigInt(value []byte) *big.Int {
    return new(big.Int).SetBytes(value)
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
    return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}
