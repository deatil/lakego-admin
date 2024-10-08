package bign

import (
    "math/big"
    "crypto/elliptic"

    bign_curve "github.com/deatil/go-cryptobin/elliptic/bign/curve"
)

func initAll() {
    initP256v1()
    initP384v1()
    initP512v1()
}

var p256v1 = &bignCurve[*bign_curve.P256Point]{
    newPoint: bign_curve.NewP256Point,
}

func initP256v1() {
    p256v1.params = &elliptic.CurveParams{
        Name:    "BIGN256V1",
        BitSize: 256,
        P:  bigFromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43"),
        N:  bigFromHex("ffffffffffffffffffffffffffffffffd95c8ed60dfb4dfc7e5abf99263d6607"),
        B:  bigFromHex("77ce6c1515f3a8edd2c13aabe4d8fbbe4cf55069978b9253b22e7d6bd69c03f1"),
        Gx: bigFromHex("0000000000000000000000000000000000000000000000000000000000000000"),
        Gy: bigFromHex("6bf7fc3cfb16d69f5ce4c9a351d6835d78913966c408f6521e29cf1804516a93"),
    }
}

var p384v1 = &bignCurve[*bign_curve.P384Point]{
    newPoint: bign_curve.NewP384Point,
}

func initP384v1() {
    p384v1.params = &elliptic.CurveParams{
        Name:    "BIGN384V1",
        BitSize: 384,
        P: bigFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec3"),
        N: bigFromHex("fffffffffffffffffffffffffffffffffffffffffffffffe6cccc40373af7bbb8046dae7a6a4ff0a3db7dc3ff30ca7b7"),
        B: bigFromHex("3c75dfe1959cef2033075aab655d34d2712748bb0ffbb196a6216af9e9712e3a14bde2f0f3cebd7cbca7fc236873bf64"),
        Gx: bigFromHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        Gy: bigFromHex("5d438224a82e9e9e6330117e432dbf893a729a11dc86ffa00549e79e66b1d35584403e276b2a42f9ea5ecb31f733c451"),
    }
}

var p512v1 = &bignCurve[*bign_curve.P512Point]{
    newPoint: bign_curve.NewP512Point,
}

func initP512v1() {
    p512v1.params = &elliptic.CurveParams{
        Name:    "BIGN512V1",
        BitSize: 512,
        P: bigFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7"),
        N: bigFromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb2c0092c0198004ef26bebb02e2113f4361bcae59556df32dcffad490d068ef1"),
        B: bigFromHex("6cb45944933b8c43d88c5d6a60fd58895bc6a9eedd5d255117ce13e3daadb0882711dcb5c4245e952933008c87aca243ea8622273a49a27a09346998d6139c90"),
        Gx: bigFromHex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        Gy: bigFromHex("a826ff7ae4037681b182e6f7a0d18fabb0ab41b3b361bce2d2edf81b00cccada6973dde20efa6fd2ff777395eee8226167aa83b9c94c0d04b792ae6fceefedbd"),
    }
}

func bigFromHex(s string) *big.Int {
    b, ok := new(big.Int).SetString(s, 16)
    if !ok {
        panic("go-cryptobin/bign: invalid encoding")
    }

    return b
}
