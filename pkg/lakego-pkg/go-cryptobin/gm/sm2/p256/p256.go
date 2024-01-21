package p256

import (
    "sync"
    "math/big"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/gm/sm2/field"
    "github.com/deatil/go-cryptobin/gm/sm2/point"
)

type P256Curve struct {
    RInverse *big.Int
    *elliptic.CurveParams
    A, b, gx, gy field.Element
}

var initonce sync.Once
var sm2P256 P256Curve

func initP256() {
    // sm2
    sm2P256.CurveParams = &elliptic.CurveParams{
        Name: "SM2-P-256",
    }

    A, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)

    sm2P256.P, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
    sm2P256.N, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
    sm2P256.B, _ = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
    sm2P256.Gx, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
    sm2P256.Gy, _ = new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
    sm2P256.RInverse, _ = new(big.Int).SetString("7ffffffd80000002fffffffe000000017ffffffe800000037ffffffc80000002", 16)
    sm2P256.BitSize = 256

    sm2P256.A.FromBig(A)
    sm2P256.gx.FromBig(sm2P256.Gx)
    sm2P256.gy.FromBig(sm2P256.Gy)
    sm2P256.b.FromBig(sm2P256.B)
}

func P256() elliptic.Curve {
    initonce.Do(initP256)
    return sm2P256
}

func (curve P256Curve) Params() *elliptic.CurveParams {
    return sm2P256.CurveParams
}

// y^2 = x^3 + ax + b
func (curve P256Curve) IsOnCurve(X, Y *big.Int) bool {
    var a, x, y, y2, x3 field.Element

    x.FromBig(X)
    y.FromBig(Y)

    x3.Square(&x)       // x3 = x ^ 2
    x3.Mul(&x3, &x)     // x3 = x ^ 2 * x

    a.Mul(&curve.A, &x) // a = a * x

    x3.Add(&x3, &a)
    x3.Add(&x3, &curve.b)

    y2.Square(&y) // y2 = y ^ 2

    return x3.ToBig().Cmp(y2.ToBig()) == 0
}

func (curve P256Curve) Add(x1, y1, x2, y2 *big.Int) (xx, yy *big.Int) {
    var a, b, c point.Point

    z1 := zForAffine(x1, y1)
    z2 := zForAffine(x2, y2)

    a.NewPoint(x1, y1, z1)
    b.NewPoint(x2, y2, z2)

    c.Add(&a, &b)

    xx, yy = new(big.Int), new(big.Int)
    return c.ToBig(xx, yy)
}

func (curve P256Curve) Double(x1, y1 *big.Int) (xx, yy *big.Int) {
    var a point.Point

    z1 := zForAffine(x1, y1)

    a.NewPoint(x1, y1, z1)
    a.Double(&a)

    xx, yy = new(big.Int), new(big.Int)
    return a.ToBig(xx, yy)
}

func (curve P256Curve) ScalarMult(x1, y1 *big.Int, k []byte) (xx, yy *big.Int) {
    var a, b point.Point

    z1 := zForAffine(x1, y1)

    b.NewPoint(x1, y1, z1)

    scalar := genrateWNaf(k)
    scalarReversed := WNafReversed(scalar)

    a.ScalarMult(&b, scalarReversed)

    xx, yy = new(big.Int), new(big.Int)
    return a.ToBig(xx, yy)
}

func (curve P256Curve) ScalarBaseMult(k []byte) (xx, yy *big.Int) {
    var scalarReversed [32]byte
    var a point.Point

    getScalar(&scalarReversed, k)

    a.ScalarBaseMult(scalarReversed)

    xx, yy = new(big.Int), new(big.Int)
    return a.ToBig(xx, yy)
}
