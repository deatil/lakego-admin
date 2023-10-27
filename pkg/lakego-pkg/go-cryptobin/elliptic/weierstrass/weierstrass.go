package weierstrass

// Support for short Weierstrass elliptic curves
// http://www.secg.org/SEC2-Ver-1.0.pdf

import (
    "sync"
    "math/big"
    "crypto/elliptic"
)

var (
    once sync.Once
    p160k1, p160r1, p160r2, p192k1, p192r1, p224k1, p256k1 *elliptic.CurveParams
)

func initAll() {
    initP160r1()
    initP160r2()
    initP192r1()
}

func initP160r1() {
    p160r1 = new(elliptic.CurveParams)
    p160r1.P, _ = new(big.Int).SetString("ffffffffffffffffffffffffffffffff7fffffff", 16)
    p160r1.N, _ = new(big.Int).SetString("0100000000000000000001f4c8f927aed3ca752257", 16)
    p160r1.B, _ = new(big.Int).SetString("1c97befc54bd7a8b65acf89f81d4d4adc565fa45", 16)
    p160r1.Gx, _ = new(big.Int).SetString("4a96b5688ef573284664698968c38bb913cbfc82", 16)
    p160r1.Gy, _ = new(big.Int).SetString("23a628553168947d59dcc912042351377ac5fb32", 16)
    p160r1.BitSize = 160
}

func initP160r2() {
    p160r2 = new(elliptic.CurveParams)
    p160r2.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73", 16)
    p160r2.N, _ = new(big.Int).SetString("0100000000000000000000351EE786A818F3A1A16B", 16)
    p160r2.B, _ = new(big.Int).SetString("B4E134D3FB59EB8BAB57274904664D5AF50388BA", 16)
    p160r2.Gx, _ = new(big.Int).SetString("52DCB034293A117E1F4FF11B30F7199D3144CE6D", 16)
    p160r2.Gy, _ = new(big.Int).SetString("FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E", 16)
    p160r2.BitSize = 160
}

func initP192r1() {
    p192r1 = new(elliptic.CurveParams)
    p192r1.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16)
    p192r1.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", 16)
    p192r1.B, _ = new(big.Int).SetString("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", 16)
    p192r1.Gx, _ = new(big.Int).SetString("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16)
    p192r1.Gy, _ = new(big.Int).SetString("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16)
    p192r1.BitSize = 192
}

func P160r1() elliptic.Curve {
    once.Do(initAll)
    return p160r1
}

func P160r2() elliptic.Curve {
    once.Do(initAll)
    return p160r2
}

func P192r1() elliptic.Curve {
    once.Do(initAll)
    return p192r1
}
