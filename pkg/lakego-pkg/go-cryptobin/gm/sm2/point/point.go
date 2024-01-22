package point

import (
    "errors"
    "math/big"

    "github.com/deatil/go-cryptobin/gm/sm2/field"
)

var feZero field.Element

var A, B, P *big.Int

func init() {
    A, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
    B, _ = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
    P, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
}

type Point struct {
    x, y field.Element
}

func (this *Point) NewPoint(x, y *big.Int) (*Point, error) {
    if x.Sign() < 0 || y.Sign() < 0 {
        return nil, errors.New("negative coordinate")
    }
    if x.BitLen() > 256 || y.BitLen() > 256 {
        return nil, errors.New("overflowing coordinate")
    }

    this.x.FromBig(x)
    this.y.FromBig(y)

    return this, nil
}

func IsOnCurve(p *Point) bool {
    var a, b, y2, x3 field.Element

    x3.Square(&p.x)  // x3 = x ^ 2
    x3.Mul(&x3, &p.x)     // x3 = x ^ 2 * x

    // a
    a.FromBig(A)
    a.Mul(&a, &p.x) // a = a * x

    b.FromBig(B)

    x3.Add(&x3, &a)
    x3.Add(&x3, &b)

    y2.Square(&p.y) // y2 = y ^ 2

    return x3.ToBig().Cmp(y2.ToBig()) == 0
}

func (this *Point) Zero() *Point {
    this.x.Zero()
    this.y.Zero()

    return this
}

func (this *Point) Set(q *Point) *Point {
    this.x.Set(&q.x)
    this.y.Set(&q.y)

    return this
}

// Select sets {out_x,out_y} to the index'th entry of table.
// On entry: index < 16, table[0] must be zero.
func (this *Point) Select(table []uint32, index uint32) *Point {
    this.x.Zero()
    this.y.Zero()

    for i := uint32(1); i < 16; i++ {
        mask := i ^ index
        mask |= mask >> 2
        mask |= mask >> 1
        mask &= 1
        mask--

        this.x.SelectAffine(table, mask)
        table = table[9:]

        this.y.SelectAffine(table, mask)
        table = table[9:]
    }

    return this
}

// FromJacobian reverses the Jacobian transform. If the point is ∞ it returns 0, 0.
func (this *Point) FromJacobian(v *PointJacobian) *Point {
    if v.z.Equal(&feZero) == 1 {
        this.x.Zero()
        this.y.Zero()
        return this
    }

    var zInv, zInvSq field.Element

    zz := v.z.ToBig()
    zz.ModInverse(zz, P)

    zInv.FromBig(zz)

    zInvSq.Square(&zInv)
    this.x.Mul(&v.x, &zInvSq)

    zInv.Mul(&zInv, &zInvSq)
    this.y.Mul(&v.y, &zInv)

    return this
}

func (this *Point) ToBig(x, y *big.Int) (xx, yy *big.Int) {
    x.Set(this.x.ToBig())
    y.Set(this.y.ToBig())

    return x, y
}
