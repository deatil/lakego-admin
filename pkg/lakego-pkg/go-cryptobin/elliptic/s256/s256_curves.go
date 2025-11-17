package s256

import (
    "math/big"
)

var s256 *S256Curve

func initAll() {
    initS256()
}

func initS256() {
    s256 = &S256Curve{
        Name:    "secp256k1",
        BitSize: 256,
        P:       bigFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
        N:       bigFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
        B:       bigFromHex("0000000000000000000000000000000000000000000000000000000000000007"),
        Gx:      bigFromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
        Gy:      bigFromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
    }
}

func bigFromHex(s string) (i *big.Int) {
    i = new(big.Int)
    i.SetString(s, 16)

    return
}
