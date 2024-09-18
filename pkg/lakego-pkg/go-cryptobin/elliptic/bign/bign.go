package bign

import (
    "sync"
    "math/big"
    "encoding/asn1"
    "crypto/elliptic"
)

var (
    OIDNamedCurveP256v1 = asn1.ObjectIdentifier{1, 2, 112, 0, 2, 0, 34, 101, 45, 3, 1}
    OIDNamedCurveP384v1 = asn1.ObjectIdentifier{1, 2, 112, 0, 2, 0, 34, 101, 45, 3, 2}
    OIDNamedCurveP512v1 = asn1.ObjectIdentifier{1, 2, 112, 0, 2, 0, 34, 101, 45, 3, 3}
)

var (
    once sync.Once
    p256v1, p384v1, p512v1 *elliptic.CurveParams
)

func initAll() {
    initP256v1()
    initP384v1()
    initP512v1()
}

func initP256v1() {
    p256v1 = new(elliptic.CurveParams)
    p256v1.P = bigFromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43")
    p256v1.N = bigFromHex("ffffffffffffffffffffffffffffffffd95c8ed60dfb4dfc7e5abf99263d6607")
    p256v1.B = bigFromHex("77ce6c1515f3a8edd2c13aabe4d8fbbe4cf55069978b9253b22e7d6bd69c03f1")
    p256v1.Gx = bigFromHex("0000000000000000000000000000000000000000000000000000000000000000")
    p256v1.Gy = bigFromHex("6bf7fc3cfb16d69f5ce4c9a351d6835d78913966c408f6521e29cf1804516a93")
    p256v1.BitSize = 256
    p256v1.Name = "BIGN256V1"
}

func initP384v1() {
    p384v1 = new(elliptic.CurveParams)
    p384v1.P = bigFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec3")
    p384v1.N = bigFromHex("fffffffffffffffffffffffffffffffffffffffffffffffe6cccc40373af7bbb8046dae7a6a4ff0a3db7dc3ff30ca7b7")
    p384v1.B = bigFromHex("3c75dfe1959cef2033075aab655d34d2712748bb0ffbb196a6216af9e9712e3a14bde2f0f3cebd7cbca7fc236873bf64")
    p384v1.Gx = bigFromHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    p384v1.Gy = bigFromHex("5d438224a82e9e9e6330117e432dbf893a729a11dc86ffa00549e79e66b1d35584403e276b2a42f9ea5ecb31f733c451")
    p384v1.BitSize = 384
    p384v1.Name = "BIGN384V1"
}

func initP512v1() {
    p512v1 = new(elliptic.CurveParams)
    p512v1.P = bigFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7")
    p512v1.N = bigFromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb2c0092c0198004ef26bebb02e2113f4361bcae59556df32dcffad490d068ef1")
    p512v1.B = bigFromHex("6cb45944933b8c43d88c5d6a60fd58895bc6a9eedd5d255117ce13e3daadb0882711dcb5c4245e952933008c87aca243ea8622273a49a27a09346998d6139c90")
    p512v1.Gx = bigFromHex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    p512v1.Gy = bigFromHex("a826ff7ae4037681b182e6f7a0d18fabb0ab41b3b361bce2d2edf81b00cccada6973dde20efa6fd2ff777395eee8226167aa83b9c94c0d04b792ae6fceefedbd")
    p512v1.BitSize = 512
    p512v1.Name = "BIGN512V1"
}

func P256v1() elliptic.Curve {
    once.Do(initAll)
    return p256v1
}

func P384v1() elliptic.Curve {
    once.Do(initAll)
    return p384v1
}

func P512v1() elliptic.Curve {
    once.Do(initAll)
    return p512v1
}

func bigFromHex(s string) *big.Int {
    b, ok := new(big.Int).SetString(s, 16)
    if !ok {
        panic("go-cryptobin/bign: internal error: invalid encoding")
    }
    return b
}
