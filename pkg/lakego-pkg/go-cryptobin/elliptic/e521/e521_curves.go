package e521

import (
    "math/big"
)

var e521 *E521Curve

func initAll() {
    initE521()
}

func initE521() {
    e521 = &E521Curve{
        Name:    "E-521",
        P:       bigFromHex("1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        N:       bigFromHex("7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd15b6c64746fc85f736b8af5e7ec53f04fbd8c4569a8f1f4540ea2435f5180d6b"),
        D:       bigFromHex("1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa4331"),
        Gx:      bigFromHex("752cb45c48648b189df90cb2296b2878a3bfd9f42fc6c818ec8bf3c9c0c6203913f6ecc5ccc72434b1ae949d568fc99c6059d0fb13364838aa302a940a2f19ba6c"),
        Gy:      bigFromHex("0c"),
        BitSize: 521,
    }
}

func bigFromHex(s string) (i *big.Int) {
    i = new(big.Int)
    i.SetString(s, 16)

    return
}
