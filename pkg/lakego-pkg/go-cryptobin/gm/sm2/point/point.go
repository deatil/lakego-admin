package point

import (
    "errors"
    "math/big"

    "github.com/deatil/go-cryptobin/gm/sm2/field"
)

var A, B, P *big.Int

func init() {
    A, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
    B, _ = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
    P, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
}

type Point struct {
    x, y, z field.Element
}

func (this *Point) NewPoint(x, y, z *big.Int) (*Point, error) {
    if x.Sign() < 0 || y.Sign() < 0  || z.Sign() < 0{
        return nil, errors.New("negative coordinate")
    }
    if x.BitLen() > 256 || y.BitLen() > 256 || z.BitLen() > 256 {
        return nil, errors.New("overflowing coordinate")
    }

    this.x.FromBig(x)
    this.y.FromBig(y)
    this.z.FromBig(z)

    return this, nil
}

func (this *Point) NewPointWithXY(x, y *big.Int) (*Point, error) {
    z := zForAffine(x, y)

    return this.NewPoint(x, y, z)
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

// z1 = a, z2 = b
func (this *Point) AddMixed(a, b *Point) *Point {
    var z1z1, z1z1z1, s2, u2, h, i, j, r, rr, v, tmp field.Element

    z1z1.Square(&a.z)
    tmp.Add(&a.z, &a.z)

    u2.Mul(&b.x, &z1z1)
    z1z1z1.Mul(&a.z, &z1z1)

    s2.Mul(&b.y, &z1z1z1)
    h.Sub(&u2, &a.x)
    i.Add(&h, &h)
    i.Square(&i)
    j.Mul(&h, &i)
    r.Sub(&s2, &a.y)
    r.Add(&r, &r)
    v.Mul(&a.x, &i)

    this.z.Mul(&tmp, &h)
    rr.Square(&r)
    this.x.Sub(&rr, &j)
    this.x.Sub(&this.x, &v)
    this.x.Sub(&this.x, &v)

    tmp.Sub(&v, &this.x)
    this.y.Mul(&tmp, &r)
    tmp.Mul(&a.y, &j)
    this.y.Sub(&this.y, &tmp)
    this.y.Sub(&this.y, &tmp)

    return this
}

// SelectAffinePoint sets {out_x,out_y} to the index'th entry of table.
// On entry: index < 16, table[0] must be zero.
func (this *Point) SelectAffinePoint(table []uint32, index uint32) *Point {
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

// SelectJacobianPoint sets {out_x,out_y,out_z} to the index'th entry of
// table.
// On entry: index < 16, table[0] must be zero.
func (this *Point) SelectJacobianPoint(table [16]Point, index uint32) *Point {
    this.x.Zero()
    this.y.Zero()
    this.z.Zero()

    // The implicit value at index 0 is all zero. We don't need to perform that
    // iteration of the loop because we already set out_* to zero.
    for i := uint32(1); i < 16; i++ {
        mask := i ^ index
        mask |= mask >> 2
        mask |= mask >> 1
        mask &= 1
        mask--

        tt0 := table[i].x
        this.x.SelectJacobian(&tt0, mask)

        tt1 := table[i].y
        this.y.SelectJacobian(&tt1, mask)

        tt2 := table[i].z
        this.z.SelectJacobian(&tt2, mask)
    }

    return this
}

// ScalarBaseMult sets {xOut,yOut,zOut} = scalar*G where scalar is a
// little-endian number. Note that the value of scalar must be less than the
// order of the group.
func (this *Point) ScalarBaseMult(scalar [32]uint8) *Point {
    nIsInfinityMask := ^uint32(0)

    var pIsNoninfiniteMask, mask, tableOffset uint32
    var p, t Point

    this.x.Zero()
    this.y.Zero()
    this.z.Zero()

    // The loop adds bits at positions 0, 64, 128 and 192, followed by
    // positions 32,96,160 and 224 and does this 32 times.
    for i := uint(0); i < 32; i++ {
        if i != 0 {
            this.Double(this)
        }

        tableOffset = 0
        for j := uint(0); j <= 32; j += 32 {
            bit0 := getBit(scalar, 31-i+j)
            bit1 := getBit(scalar, 95-i+j)
            bit2 := getBit(scalar, 159-i+j)
            bit3 := getBit(scalar, 223-i+j)

            index := bit0 | (bit1 << 1) | (bit2 << 2) | (bit3 << 3)

            p.SelectAffinePoint(precomputed[tableOffset:], index)

            tableOffset += 30 * 9

            // Since scalar is less than the order of the group, we know that
            // {xOut,yOut,zOut} != {px,py,1}, unless both are zero, which we handle
            // below.
            t.AddMixed(this, &p)

            // The result of pointAddMixed is incorrect if {xOut,yOut,zOut} is zero
            // (a.k.a.  the point at infinity). We handle that situation by
            // copying the point from the table.
            this.x.CopyConditional(&p.x, nIsInfinityMask)
            this.y.CopyConditional(&p.y, nIsInfinityMask)
            this.z.CopyConditional(&field.Factor[1], nIsInfinityMask)

            // Equally, the result is also wrong if the point from the table is
            // zero, which happens when the index is zero. We handle that by
            // only copying from {tx,ty,tz} to {xOut,yOut,zOut} if index != 0.
            pIsNoninfiniteMask = nonZeroToAllOnes(index)

            mask = pIsNoninfiniteMask & ^nIsInfinityMask
            this.x.CopyConditional(&t.x, mask)
            this.y.CopyConditional(&t.y, mask)
            this.z.CopyConditional(&t.z, mask)

            // If p was not zero, then n is now non-zero.
            nIsInfinityMask &^= pIsNoninfiniteMask
        }
    }

    return this
}

func (this *Point) ScalarMult(q *Point, scalar []int8) *Point {
    var precomp [16]Point
    var p, t Point
    var nIsInfinityMask, index, pIsNoninfiniteMask, mask uint32

    // We precompute 0,1,2,... times {x,y}.
    precomp[1].NewPoint(q.x.ToBig(), q.y.ToBig(), field.Factor[1].ToBig())

    for i := 2; i < 8; i += 2 {
        precomp[i].Double(&precomp[i/2])
        precomp[i+1].AddMixed(&precomp[i], q)
    }

    this.x.Zero()
    this.y.Zero()
    this.z.Zero()

    nIsInfinityMask = ^uint32(0)

    var zeroes int16
    for i := 0; i < len(scalar); i++ {
        if scalar[i] == 0 {
            zeroes++
            continue
        }

        if zeroes > 0 {
            for  ; zeroes > 0; zeroes-- {
                this.Double(this)
            }
        }

        index = abs(scalar[i])

        this.Double(this)
        p.SelectJacobianPoint(precomp, index)

        if scalar[i] > 0 {
            t.Add(this, &p)
        } else {
            t.Sub(this, &p)
        }

        this.x.CopyConditional(&p.x, nIsInfinityMask)
        this.y.CopyConditional(&p.y, nIsInfinityMask)
        this.z.CopyConditional(&p.z, nIsInfinityMask)

        pIsNoninfiniteMask = nonZeroToAllOnes(index)

        mask = pIsNoninfiniteMask & ^nIsInfinityMask

        this.x.CopyConditional(&t.x, mask)
        this.y.CopyConditional(&t.y, mask)
        this.z.CopyConditional(&t.z, mask)

        nIsInfinityMask &^= pIsNoninfiniteMask
    }

    if zeroes > 0 {
        for  ; zeroes > 0; zeroes-- {
            this.Double(this)
        }
    }

    return this
}

func (this *Point) ToAffine() (x, y field.Element) {
    var zInv, zInvSq field.Element

    zz := this.z.ToBig()
    zz.ModInverse(zz, P)

    zInv.FromBig(zz)

    zInvSq.Square(&zInv)
    x.Mul(&this.x, &zInvSq)

    zInv.Mul(&zInv, &zInvSq)
    y.Mul(&this.y, &zInv)

    return
}

func (this *Point) ToBig(x, y *big.Int) (xx, yy *big.Int) {
    x1, y1 := this.ToAffine()

    x.Set(x1.ToBig())
    y.Set(y1.ToBig())

    return x, y
}

// (x3, y3, z3) = (x1, y1, z1) + (x2, y2, z2)
// this = a + b
func (this *Point) Add(a, b *Point) *Point {
    var u1, u2, z22, z12, z23, z13, s1, s2, h, h2, r, r2, tm field.Element

    if a.z.ToBig().Sign() == 0 {
        this.x.Dup(&b.x)
        this.y.Dup(&b.y)
        this.z.Dup(&b.z)
        return this
    }

    if b.z.ToBig().Sign() == 0 {
        this.x.Dup(&a.x)
        this.y.Dup(&a.y)
        this.z.Dup(&a.z)
        return this
    }

    z12.Square(&a.z) // z12 = z1 ^ 2
    z22.Square(&b.z) // z22 = z2 ^ 2

    z13.Mul(&z12, &a.z) // z13 = z1 ^ 3
    z23.Mul(&z22, &b.z) // z23 = z2 ^ 3

    u1.Mul(&a.x, &z22) // u1 = x1 * z2 ^ 2
    u2.Mul(&b.x, &z12) // u2 = x2 * z1 ^ 2

    s1.Mul(&a.y, &z23) // s1 = y1 * z2 ^ 3
    s2.Mul(&b.y, &z13) // s2 = y2 * z1 ^ 3

    if u1.ToBig().Cmp(u2.ToBig()) == 0 &&
        s1.ToBig().Cmp(s2.ToBig()) == 0 {
        a.Double(a)
    }

    h.Sub(&u2, &u1) // h = u2 - u1
    r.Sub(&s2, &s1) // r = s2 - s1

    r2.Square(&r) // r2 = r ^ 2
    h2.Square(&h) // h2 = h ^ 2

    tm.Mul(&h2, &h) // tm = h ^ 3
    this.x.Sub(&r2, &tm)
    tm.Mul(&u1, &h2)
    tm.Scalar(2)   // tm = 2 * (u1 * h ^ 2)
    this.x.Sub(&this.x, &tm) // x3 = r ^ 2 - h ^ 3 - 2 * u1 * h ^ 2

    tm.Mul(&u1, &h2) // tm = u1 * h ^ 2
    tm.Sub(&tm, &this.x)  // tm = u1 * h ^ 2 - x3
    this.y.Mul(&r, &tm)
    tm.Mul(&h2, &h)  // tm = h ^ 3
    tm.Mul(&tm, &s1) // tm = s1 * h ^ 3
    this.y.Sub(&this.y, &tm)   // y3 = r * (u1 * h ^ 2 - x3) - s1 * h ^ 3

    this.z.Mul(&a.z, &b.z)
    this.z.Mul(&this.z, &h) // z3 = z1 * z3 * h

    return this
}

// (x3, y3, z3) = (x1, y1, z1)- (x2, y2, z2)
// this = a + b
func (this *Point) Sub(a, b *Point) *Point {
    var u1, u2, z22, z12, z23, z13, s1, s2, h, h2, r, r2, tm field.Element

    y := b.y.ToBig()
    zero := new(big.Int).SetInt64(0)

    y.Sub(zero, y)

    b.y.FromBig(y)

    if a.z.ToBig().Sign() == 0 {
        this.x.Dup(&b.x)
        this.y.Dup(&b.y)
        this.z.Dup(&b.z)
        return this
    }

    if b.z.ToBig().Sign() == 0 {
        this.x.Dup(&a.x)
        this.y.Dup(&a.y)
        this.z.Dup(&a.z)
        return this
    }

    z12.Square(&a.z) // z12 = z1 ^ 2
    z22.Square(&b.z) // z22 = z2 ^ 2

    z13.Mul(&z12, &a.z) // z13 = z1 ^ 3
    z23.Mul(&z22, &b.z) // z23 = z2 ^ 3

    u1.Mul(&a.x, &z22) // u1 = x1 * z2 ^ 2
    u2.Mul(&b.x, &z12) // u2 = x2 * z1 ^ 2

    s1.Mul(&a.y, &z23) // s1 = y1 * z2 ^ 3
    s2.Mul(&b.y, &z13) // s2 = y2 * z1 ^ 3

    if u1.ToBig().Cmp(u2.ToBig()) == 0 &&
        s1.ToBig().Cmp(s2.ToBig()) == 0 {
        a.Double(a)
    }

    h.Sub(&u2, &u1) // h = u2 - u1
    r.Sub(&s2, &s1) // r = s2 - s1

    r2.Square(&r) // r2 = r ^ 2
    h2.Square(&h) // h2 = h ^ 2

    tm.Mul(&h2, &h) // tm = h ^ 3
    this.x.Sub(&r2, &tm)
    tm.Mul(&u1, &h2)
    tm.Scalar(2)   // tm = 2 * (u1 * h ^ 2)
    this.x.Sub(&this.x, &tm) // x3 = r ^ 2 - h ^ 3 - 2 * u1 * h ^ 2

    tm.Mul(&u1, &h2) // tm = u1 * h ^ 2
    tm.Sub(&tm, &this.x)  // tm = u1 * h ^ 2 - x3
    this.y.Mul(&r, &tm)
    tm.Mul(&h2, &h)  // tm = h ^ 3
    tm.Mul(&tm, &s1) // tm = s1 * h ^ 3
    this.y.Sub(&this.y, &tm)   // y3 = r * (u1 * h ^ 2 - x3) - s1 * h ^ 3

    this.z.Mul(&a.z, &b.z)
    this.z.Mul(&this.z, &h) // z3 = z1 * z3 * h

    return this
}

func (this *Point) Double(v *Point) *Point {
    var a, s, m, m2, x2, y2, z2, z4, y4, az4 field.Element

    x2.Square(&v.x) // x2 = x ^ 2
    y2.Square(&v.y) // y2 = y ^ 2
    z2.Square(&v.z) // z2 = z ^ 2

    z4.Square(&v.z)   // z4 = z ^ 2
    z4.Mul(&z4, &v.z) // z4 = z ^ 3
    z4.Mul(&z4, &v.z) // z4 = z ^ 4

    y4.Square(&v.y)   // y4 = y ^ 2
    y4.Mul(&y4, &v.y) // y4 = y ^ 3
    y4.Mul(&y4, &v.y) // y4 = y ^ 4
    y4.Scalar(8)   // y4 = 8 * y ^ 4

    s.Mul(&v.x, &y2)
    s.Scalar(4) // s = 4 * x * y ^ 2

    // a
    a.FromBig(A)

    m.Dup(&x2)
    m.Scalar(3)
    az4.Mul(&a, &z4)
    m.Add(&m, &az4) // m = 3 * x ^ 2 + a * z ^ 4

    m2.Square(&m) // m2 = m ^ 2

    this.z.Add(&v.y, &v.z)
    this.z.Square(&this.z)
    this.z.Sub(&this.z, &z2)
    this.z.Sub(&this.z, &y2) // z' = (y + z) ^2 - z ^ 2 - y ^ 2

    this.x.Sub(&m2, &s)
    this.x.Sub(&this.x, &s) // x' = m2 - 2 * s

    this.y.Sub(&s, &this.x)
    this.y.Mul(&this.y, &m)
    this.y.Sub(&this.y, &y4) // y' = m * (s - x') - 8 * y ^ 4

    return this
}
