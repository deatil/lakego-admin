package secp

import (
    "sync"
    "math/big"
    "crypto/elliptic"
)

var (
    once sync.Once
    secp192r1 *elliptic.CurveParams
    secp112r1, secp112r2 *elliptic.CurveParams
    secp128r1, secp128r2 *elliptic.CurveParams
    secp160r1, secp160r2 *elliptic.CurveParams
)

func initAll() {
    initP192()

    initSecp112r1()
    initSecp112r2()
    initSecp128r1()
    initSecp128r2()
    initSecp160r1()
    initSecp160r2()
}

func initSecp112r1() {
    // p = (2^128 - 3) / 76439
    secp112r1 = new(elliptic.CurveParams)
    secp112r1.P = bigFromHex("DB7C2ABF62E35E668076BEAD208B")
    secp112r1.N = bigFromHex("DB7C2ABF62E35E7628DFAC6561C5")
    secp112r1.B = bigFromHex("659EF8BA043916EEDE8911702B22")
    secp112r1.Gx = bigFromHex("09487239995A5EE76B55F9C2F098")
    secp112r1.Gy = bigFromHex("A89CE5AF8724C0A23E0E0FF77500")
    secp112r1.BitSize = 112
    secp112r1.Name = "secp112r1"
}

func initSecp112r2() {
    // p = (2^128 - 3) / 76439
    secp112r2 = new(elliptic.CurveParams)
    secp112r2.P = bigFromHex("DB7C2ABF62E35E668076BEAD208B")
    secp112r2.N = bigFromHex("36DF0AAFD8B8D7597CA10520D04B")
    secp112r2.B = bigFromHex("51DEF1815DB5ED74FCC34C85D709")
    secp112r2.Gx = bigFromHex("4BA30AB5E892B4E1649DD0928643")
    secp112r2.Gy = bigFromHex("ADCD46F5882E3747DEF36E956E97")
    secp112r2.BitSize = 112
    secp112r2.Name = "secp112r2"
}

func initSecp128r1() {
    // p = 2^128 - 2^97 - 1
    secp128r1 = new(elliptic.CurveParams)
    secp128r1.P = bigFromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF")
    secp128r1.N = bigFromHex("FFFFFFFE0000000075A30D1B9038A115")
    secp128r1.B = bigFromHex("E87579C11079F43DD824993C2CEE5ED3")
    secp128r1.Gx = bigFromHex("161FF7528B899B2D0C28607CA52C5B86")
    secp128r1.Gy = bigFromHex("CF5AC8395BAFEB13C02DA292DDED7A83")
    secp128r1.BitSize = 128
    secp128r1.Name = "secp128r1"
}

func initSecp128r2() {
    // p = 2^128 - 2^97 - 1
    secp128r2 = new(elliptic.CurveParams)
    secp128r2.P = bigFromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF")
    secp128r2.N = bigFromHex("3FFFFFFF7FFFFFFFBE0024720613B5A3")
    secp128r2.B = bigFromHex("5EEEFCA380D02919DC2C6558BB6D8A5D")
    secp128r2.Gx = bigFromHex("7B6AA5D85E572983E6FB32A7CDEBC140")
    secp128r2.Gy = bigFromHex("27B6916A894D3AEE7106FE805FC34B44")
    secp128r2.BitSize = 128
    secp128r2.Name = "secp128r2"
}

func initSecp160r1() {
    // p = 2^160 - 2^31 - 1
    secp160r1 = new(elliptic.CurveParams)
    secp160r1.P = bigFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF")
    secp160r1.N = bigFromHex("0100000000000000000001F4C8F927AED3CA752257")
    secp160r1.B = bigFromHex("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45")
    secp160r1.Gx = bigFromHex("4A96B5688EF573284664698968C38BB913CBFC82")
    secp160r1.Gy = bigFromHex("23A628553168947D59DCC912042351377AC5FB32")
    secp160r1.BitSize = 160
    secp160r1.Name = "secp160r1"
}

func initSecp160r2() {
    // p = 2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 1
    secp160r2 = new(elliptic.CurveParams)
    secp160r2.P = bigFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73")
    secp160r2.N = bigFromHex("0100000000000000000000351EE786A818F3A1A16B")
    secp160r2.B = bigFromHex("B4E134D3FB59EB8BAB57274904664D5AF50388BA")
    secp160r2.Gx = bigFromHex("52DCB034293A117E1F4FF11B30F7199D3144CE6D")
    secp160r2.Gy = bigFromHex("FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E")
    secp160r2.BitSize = 160
    secp160r2.Name = "secp160r2"
}

func initP192() {
    // p = 2^192 - 2^64 - 1
    secp192r1 = new(elliptic.CurveParams)
    secp192r1.P = bigFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF")
    secp192r1.N = bigFromHex("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831")
    secp192r1.B = bigFromHex("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1")
    secp192r1.Gx = bigFromHex("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012")
    secp192r1.Gy = bigFromHex("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811")
    secp192r1.BitSize = 192
    secp192r1.Name = "secp192r1"
}

func bigFromHex(s string) *big.Int {
    b, ok := new(big.Int).SetString(s, 16)
    if !ok {
        panic("go-cryptobin/secp: invalid encoding")
    }

    return b
}
