package frp256v1

import (
    "sync"
    "math/big"
    "encoding/asn1"
    "crypto/elliptic"
)

// ANSSI EC

var (
    OIDNamedCurveFRP256v1 = asn1.ObjectIdentifier{1, 2, 250, 1, 223, 101, 256, 1}
)

var (
    once sync.Once
    frp256v1 *elliptic.CurveParams
)

func initAll() {
    initFRP256v1()
}

func initFRP256v1() {
    frp256v1 = new(elliptic.CurveParams)
    frp256v1.P = bigFromHex("F1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C03")
    frp256v1.N = bigFromHex("F1FD178C0B3AD58F10126DE8CE42435B53DC67E140D2BF941FFDD459C6D655E1")
    frp256v1.B = bigFromHex("EE353FCA5428A9300D4ABA754A44C00FDFEC0C9AE4B1A1803075ED967B7BB73F")
    frp256v1.Gx = bigFromHex("B6B3D4C356C139EB31183D4749D423958C27D2DCAF98B70164C97A2DD98F5CFF")
    frp256v1.Gy = bigFromHex("6142E0F7C8B204911F9271F0F3ECEF8C2701C307E8E4C9E183115A1554062CFB")
    frp256v1.BitSize = 256
    frp256v1.Name = "FRP256v1"
}

func FRP256v1() elliptic.Curve {
    once.Do(initAll)
    return frp256v1
}

func bigFromHex(s string) *big.Int {
    b, ok := new(big.Int).SetString(s, 16)
    if !ok {
        panic("go-cryptobin/frp256v1: invalid encoding")
    }

    return b
}
