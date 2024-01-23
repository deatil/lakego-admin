package point

import (
    "errors"
    "math/big"

    "github.com/deatil/go-cryptobin/gm/sm2/field"
)

var (
    feZero field.Element

    A, P *big.Int
)

func init() {
    A, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
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

// Select sets {out_x,out_y} to the cond'th entry of table.
// On entry: cond < 16, table[0] must be zero.
func (this *Point) Select(a *Point, cond uint32) *Point {
    this.x.Select(&a.x, cond)
    this.y.Select(&a.y, cond)

    return this
}

// FromJacobian reverses the Jacobian transform. If the point is ∞ it returns 0, 0.
func (this *Point) FromJacobian(v *PointJacobian) *Point {
    if v.z.Equal(&feZero) == 1 {
        this.Zero()
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
