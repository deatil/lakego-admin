package p256

import (
    "sync"
    "errors"
    "math/big"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/gm/sm2/field"
    "github.com/deatil/go-cryptobin/gm/sm2/point"
)

var (
    initonce sync.Once
    sm2P256  sm2Curve
)

type CurveParams struct {
    Name    string
    BitSize int
    P       *big.Int
    A, B    field.Element // params
    Gx, Gy  *big.Int      // generator
    N       *big.Int      // order
}

type Curve interface {
    elliptic.Curve
    BinaryParams() *CurveParams
}

type sm2Curve struct {
    params *CurveParams
}

var _ elliptic.Curve = (*sm2Curve)(nil)

func initP256() {
    sm2P256.params = &CurveParams{
        Name:    "SM2-P-256",
        BitSize: 256,
        P:  bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"),
        N:  bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"),
        Gx: bigFromHex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"),
        Gy: bigFromHex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"),
    }

    sm2P256.params.A.FromBig(bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"))
    sm2P256.params.B.FromBig(bigFromHex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"))
}

func P256() Curve {
    initonce.Do(initP256)
    return sm2P256
}

func (curve sm2Curve) Params() *elliptic.CurveParams {
    return &elliptic.CurveParams{
        P:       curve.params.P,
        N:       curve.params.N,
        B:       curve.params.B.ToBig(),
        Gx:      curve.params.Gx,
        Gy:      curve.params.Gy,
        BitSize: curve.params.BitSize,
        Name:    curve.params.Name,
    }
}

func (curve sm2Curve) BinaryParams() *CurveParams {
    return curve.params
}

// y^2 = x^3 + ax + b
func (curve sm2Curve) IsOnCurve(x, y *big.Int) bool {
    var a, x1, y1, y2, x3 field.Element

    x1.FromBig(x)
    y1.FromBig(y)

    x3.Square(&x1)   // x3 = x ^ 2
    x3.Mul(&x3, &x1) // x3 = x ^ 2 * x

    a.Mul(&curve.params.A, &x1)   // a = a * x

    x3.Add(&x3, &a)
    x3.Add(&x3, &curve.params.B)

    y2.Square(&y1) // y2 = y ^ 2

    return x3.ToBig().Cmp(y2.ToBig()) == 0
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

func (curve sm2Curve) Double(x, y *big.Int) (xx, yy *big.Int) {
    a, err := curve.pointFromAffine(x, y)
    if err != nil {
        panic("cryptobin/sm2Curve: Double was called on an invalid point")
    }

    a.Double(&a)

    return curve.pointToAffine(a)
}

func (curve sm2Curve) ScalarMult(x, y *big.Int, k []byte) (xx, yy *big.Int) {
    a, err := curve.pointFromAffine(x, y)
    if err != nil {
        panic("cryptobin/sm2Curve: ScalarMult was called on an invalid point")
    }

    scalar := curve.genrateWNaf(k)
    scalar = curve.wnafReversed(scalar)

    var b point.PointJacobian
    b.ScalarMult(&a, scalar)

    return curve.pointToAffine(b)
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
        return p, errors.New("cryptobin/sm2Curve: negative coordinate")
    }

    params := curve.Params()
    if params == nil {
        return p, errors.New("cryptobin/sm2Curve: params coordinate")
    }

    if x.BitLen() > params.BitSize || y.BitLen() > params.BitSize {
        return p, errors.New("cryptobin/sm2Curve: overflowing coordinate")
    }

    var a point.Point
    var b point.PointJacobian

    _, err = a.NewPoint(x, y)
    if err != nil {
        return p, err
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

    params := curve.Params()

    n := new(big.Int).SetBytes(scalar)
    if n.Cmp(params.N) >= 0 {
        n.Mod(n, params.N)
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

    params := curve.Params()

    var k *big.Int
    if n.Cmp(params.N) >= 0 {
        n.Mod(n, params.N)
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
