package p256

import (
    "sync"
    "math/big"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/gm/sm2/field"
    "github.com/deatil/go-cryptobin/gm/sm2/point"
)

type sm2Curve struct {
    RInverse *big.Int
    *elliptic.CurveParams
    A, b, gx, gy field.Element
}

var initonce sync.Once
var sm2P256 sm2Curve

func initP256() {
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

func (curve sm2Curve) Params() *elliptic.CurveParams {
    return sm2P256.CurveParams
}

// y^2 = x^3 + ax + b
func (curve sm2Curve) IsOnCurve(x, y *big.Int) bool {
    var a point.Point
    a.NewPointWithXY(x, y)

    return point.IsOnCurve(&a)
}

func (curve sm2Curve) Add(x1, y1, x2, y2 *big.Int) (xx, yy *big.Int) {
    var a, b, c point.Point

    a.NewPointWithXY(x1, y1)
    b.NewPointWithXY(x2, y2)

    c.Add(&a, &b)

    xx, yy = new(big.Int), new(big.Int)
    return c.ToBig(xx, yy)
}

func (curve sm2Curve) Double(x1, y1 *big.Int) (xx, yy *big.Int) {
    var a point.Point

    a.NewPointWithXY(x1, y1)
    a.Double(&a)

    xx, yy = new(big.Int), new(big.Int)
    return a.ToBig(xx, yy)
}

func (curve sm2Curve) ScalarMult(x1, y1 *big.Int, k []byte) (xx, yy *big.Int) {
    var a, b point.Point

    b.NewPointWithXY(x1, y1)

    scalar := genrateWNaf(k)
    scalarReversed := WNafReversed(scalar)

    a.ScalarMult(&b, scalarReversed)

    xx, yy = new(big.Int), new(big.Int)
    return a.ToBig(xx, yy)
}

func (curve sm2Curve) ScalarBaseMult(k []byte) (xx, yy *big.Int) {
    var scalarReversed [32]byte
    var a point.Point

    scalarReversed = getScalar(k)

    a.ScalarBaseMult(scalarReversed)

    xx, yy = new(big.Int), new(big.Int)
    return a.ToBig(xx, yy)
}

func getScalar(a []byte) [32]byte {
    var scalarBytes []byte
    var b [32]byte

    n := new(big.Int).SetBytes(a)
    if n.Cmp(sm2P256.N) >= 0 {
        n.Mod(n, sm2P256.N)
        scalarBytes = n.Bytes()
    } else {
        scalarBytes = a
    }

    for i, v := range scalarBytes {
        b[len(scalarBytes) - (1+i)] = v
    }

    return b
}

func WNafReversed(wnaf []int8) []int8 {
    wnafRev := make([]int8, len(wnaf))

    for i, v := range wnaf {
        wnafRev[len(wnaf)-(1+i)] = v
    }

    return wnafRev
}

func genrateWNaf(b []byte) []int8 {
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

func boolToUint(b bool) uint {
    if b {
        return 1
    }

    return 0
}
