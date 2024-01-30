package sm2curve

import (
    "sync"
    "crypto/elliptic"
)

var initonce sync.Once

var p256 = &sm2Curve{
    newPoint: NewPoint,
}

func initP256() {
    p256.params = &elliptic.CurveParams{
        Name:    "SM2-P-256",
        BitSize: 256,
        P:       bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"),
        N:       bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"),
        B:       bigFromHex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"),
        Gx:      bigFromHex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"),
        Gy:      bigFromHex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"),
    }
}

func P256() elliptic.Curve {
    initonce.Do(initP256)
    return p256
}
