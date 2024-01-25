package curve

import (
    "errors"
    "math/big"

    "github.com/deatil/go-cryptobin/gm/sm2/curve/field"
)

var A, P *big.Int

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

var generator Point

func init() {
    x, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
    y, _ := new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)

    generator.x.FromBig(x)
    generator.y.FromBig(y)
}

func (this *Point) NewGenerator() *Point {
    this.Set(&generator)
    return this
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
    if v.z.IsZero() == 1 {
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
