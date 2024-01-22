package p256

import (
    "sync"
    "errors"
    "math/big"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/gm/sm2/field"
    "github.com/deatil/go-cryptobin/gm/sm2/point"
)

type sm2Curve struct {
    RInverse *big.Int
    *elliptic.CurveParams
    a, b, gx, gy field.Element
}

var A *big.Int

var initonce sync.Once
var sm2P256 sm2Curve

func initP256() {
    sm2P256.CurveParams = &elliptic.CurveParams{
        Name: "SM2-P-256",
    }

    A, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)

    sm2P256.P, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
    sm2P256.N, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
    sm2P256.B, _ = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
    sm2P256.Gx, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
    sm2P256.Gy, _ = new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
    sm2P256.RInverse, _ = new(big.Int).SetString("7ffffffd80000002fffffffe000000017ffffffe800000037ffffffc80000002", 16)
    sm2P256.BitSize = 256

    sm2P256.a.FromBig(A)
    sm2P256.gx.FromBig(sm2P256.Gx)
    sm2P256.gy.FromBig(sm2P256.Gy)
    sm2P256.b.FromBig(sm2P256.B)
}

func P256() elliptic.Curve {
    initonce.Do(initP256)
    return sm2P256
}

func (curve sm2Curve) Params() *elliptic.CurveParams {
    return sm2P256.CurveParams
}

// y^2 = x^3 + ax + b
func (curve sm2Curve) IsOnCurve(x, y *big.Int) bool {
    var a point.Point
    a.NewPoint(x, y)

    return point.IsOnCurve(&a)
}

func (curve sm2Curve) Add(x1, y1, x2, y2 *big.Int) (xx, yy *big.Int) {
    a, err := curve.pointFromAffine(x1, y1)
    if err != nil {
        panic("cryptobin/sm2Curve: Add was called on an invalid point")
    }

    b, err := curve.pointFromAffine(x2, y2)
    if err != nil {
        panic("cryptobin/sm2Curve: Add was called on an invalid point")
    }

    var c point.PointJacobian
    c.Add(&a, &b)

    return curve.pointToAffine(c)
}

func (curve sm2Curve) Double(x1, y1 *big.Int) (xx, yy *big.Int) {
    a, err := curve.pointFromAffine(x1, y1)
    if err != nil {
        panic("cryptobin/sm2Curve: Double was called on an invalid point")
    }

    a.Double(&a)

    return curve.pointToAffine(a)
}

func (curve sm2Curve) ScalarMult(x1, y1 *big.Int, k []byte) (xx, yy *big.Int) {
    b, err := curve.pointFromAffine(x1, y1)
    if err != nil {
        panic("cryptobin/sm2Curve: ScalarMult was called on an invalid point")
    }

    scalar := curve.genrateWNaf(k)
    scalarReversed := curve.wnafReversed(scalar)

    var a point.PointJacobian
    a.ScalarMult(&b, scalarReversed)

    return curve.pointToAffine(a)
}

func (curve sm2Curve) ScalarBaseMult(k []byte) (xx, yy *big.Int) {
    scalarReversed := curve.normalizeScalar(k)

    var a point.PointJacobian
    a.ScalarBaseMult(scalarReversed)

    return curve.pointToAffine(a)
}

func (curve sm2Curve) pointFromAffine(x, y *big.Int) (p point.PointJacobian, err error) {
    if x.Sign() == 0 && y.Sign() == 0 {
        return point.PointJacobian{}, nil
    }

    if x.Sign() < 0 || y.Sign() < 0 {
        return p, errors.New("negative coordinate")
    }

    params := curve.Params()
    if params == nil {
        return p, errors.New("params coordinate")
    }

    if x.BitLen() > params.BitSize || y.BitLen() > params.BitSize {
        return p, errors.New("overflowing coordinate")
    }

    var a point.Point
    var b point.PointJacobian

    _, err = a.NewPoint(x, y)
    if err != nil {
        return
    }

    b.FromAffine(&a)

    return b, nil
}

func (curve sm2Curve) pointToAffine(p point.PointJacobian) (x, y *big.Int) {
    var a point.Point

    x, y = new(big.Int), new(big.Int)
    return a.FromJacobian(&p).ToBig(x, y)
}

func (curve sm2Curve) normalizeScalar(scalar []byte) []byte {
    var b [32]byte
    var scalarBytes []byte

    n := new(big.Int).SetBytes(scalar)
    if n.Cmp(sm2P256.N) >= 0 {
        n.Mod(n, sm2P256.N)
        scalarBytes = n.Bytes()
    } else {
        scalarBytes = scalar
    }

    for i, v := range scalarBytes {
        b[len(scalarBytes) - (1+i)] = v
    }

    return b[:]
}

func (curve sm2Curve) genrateWNaf(b []byte) []int8 {
    n:= new(big.Int).SetBytes(b)

    var k *big.Int
    if n.Cmp(sm2P256.N) >= 0 {
        n.Mod(n, sm2P256.N)
        k = n
    } else {
        k = n
    }

    wnaf := make([]int8, k.BitLen()+1, k.BitLen()+1)
    if k.Sign() == 0 {
        return wnaf
    }

    var width, pow2, sign int
    width, pow2, sign = 4, 16, 8

    var mask int64 = 15
    var carry bool
    var length, pos int

    for pos <= k.BitLen() {
        if k.Bit(pos) == boolToUint(carry) {
            pos++
            continue
        }

        k.Rsh(k, uint(pos))

        var digit int
        digit = int(k.Int64() & mask)
        if carry {
            digit++
        }

        carry = (digit & sign) != 0
        if carry {
            digit -= pow2
        }

        length += pos
        wnaf[length] = int8(digit)

        pos = int(width)
    }

    if len(wnaf) > length + 1 {
        t := make([]int8, length+1, length+1)
        copy(t, wnaf[0:length+1])

        wnaf = t
    }

    return wnaf
}

func (curve sm2Curve) wnafReversed(wnaf []int8) []int8 {
    wnafRev := make([]int8, len(wnaf))

    for i, v := range wnaf {
        wnafRev[len(wnaf)-(1+i)] = v
    }

    return wnafRev
}

func boolToUint(b bool) uint {
    if b {
        return 1
    }

    return 0
}
