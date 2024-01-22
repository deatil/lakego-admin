package point

import (
    "math/big"

    "github.com/deatil/go-cryptobin/gm/sm2/field"
)

type incomparable [0]func()

type PointJacobian struct {
    x, y, z field.Element

    // Make the type not comparable (i.e. used with == or as a map key), as
    // equivalent points can be represented by different Go values.
    _ incomparable
}

func (this *PointJacobian) Zero() *PointJacobian {
    this.x.Zero()
    this.y.Zero()
    this.z.Zero()

    return this
}

func (this *PointJacobian) Set(v *PointJacobian) *PointJacobian {
    this.x.Set(&v.x)
    this.y.Set(&v.y)
    this.z.Set(&v.z)

    return this
}

// Select sets {out_x,out_y,out_z} to the index'th entry of
// table.
// On entry: index < 16, table[0] must be zero.
func (this *PointJacobian) Select(table []PointJacobian, index uint32) *PointJacobian {
    this.Zero()

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

func (this *PointJacobian) FromAffine(v *Point) *PointJacobian {
    this.x.Set(&v.x)
    this.y.Set(&v.y)

    z := zForAffine(v.x.ToBig(), v.y.ToBig())
    this.z.FromBig(z)

    return this
}

// Equal returns 1 if v and u are equal, and 0 otherwise.
func (this *PointJacobian) Equal(v *PointJacobian) int {
    var x1, y1 field.Element
    var x2, y2 field.Element

    // z1^2, z2^2, z1^3, z2^3
    var zz1, zz2, zzz1, zzz2 field.Element
    zz1.Square(&this.z)
    zzz1.Mul(&zz1, &this.z)
    zz2.Square(&v.z)
    zzz2.Mul(&zz2, &v.z)

    x1.Mul(&this.x, &zz2)
    x2.Mul(&v.x, &zz1)
    y1.Mul(&this.y, &zzz2)
    y2.Mul(&v.y, &zzz1)

    zero1 := this.z.IsZero()
    zero2 := v.z.IsZero()

    return (x1.Equal(&x2) & y1.Equal(&y2) & ^zero1 & ^zero2) | (zero1 & zero2)
}

// z1 = a, z2 = b
func (this *PointJacobian) AddMixed(a *PointJacobian, b *Point) *PointJacobian {
    var z1z1, z1z1z1, s2, u2 field.Element
    var h, i, j, r, rr, v, tmp field.Element

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

// ScalarBaseMult sets {xOut,yOut,zOut} = scalar*G where scalar is a
// little-endian number. Note that the value of scalar must be less than the
// order of the group.
func (this *PointJacobian) ScalarBaseMult(scalar []byte) *PointJacobian {
    var nIsInfinityMask, pIsNoninfiniteMask, mask, tableOffset uint32
    var p Point
    var t PointJacobian

    nIsInfinityMask = ^uint32(0)

    this.Zero()

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

            p.Select(precomputed[tableOffset:], index)

            tableOffset += 30 * 9

            // Since scalar is less than the order of the group, we know that
            // {xOut,yOut,zOut} != {px,py,1}, unless both are zero, which we handle
            // below.
            t.AddMixed(this, &p)

            // The result of pointAddMixed is incorrect if {xOut,yOut,zOut} is zero
            // (a.k.a.  the point at infinity). We handle that situation by
            // copying the point from the table.
            this.x.Select(&p.x, nIsInfinityMask)
            this.y.Select(&p.y, nIsInfinityMask)
            this.z.Select(&field.Factor[1], nIsInfinityMask)

            // Equally, the result is also wrong if the point from the table is
            // zero, which happens when the index is zero. We handle that by
            // only copying from {tx,ty,tz} to {xOut,yOut,zOut} if index != 0.
            pIsNoninfiniteMask = nonZeroToAllOnes(index)

            mask = pIsNoninfiniteMask & ^nIsInfinityMask
            this.x.Select(&t.x, mask)
            this.y.Select(&t.y, mask)
            this.z.Select(&t.z, mask)

            // If p was not zero, then n is now non-zero.
            nIsInfinityMask &^= pIsNoninfiniteMask
        }
    }

    return this
}

func (this *PointJacobian) ScalarMult(q *PointJacobian, scalar []int8) *PointJacobian {
    var precomp [16]PointJacobian
    var p, t PointJacobian
    var q2 Point
    var nIsInfinityMask, index, pIsNoninfiniteMask, mask uint32

    // We precompute 0,1,2,... times {x,y}.
    precomp[1] = PointJacobian{
        x: q.x,
        y: q.y,
        z: field.Factor[1],
    }

    for i := 2; i < 8; i += 2 {
        precomp[i].Double(&precomp[i/2])
        precomp[i+1].AddMixed(&precomp[i], q2.FromJacobian(q))
    }

    this.Zero()

    nIsInfinityMask = ^uint32(0)

    var zeroes int16
    for i := 0; i < len(scalar); i++ {
        if scalar[i] == 0 {
            zeroes++
            continue
        }

        if zeroes > 0 {
            for ; zeroes > 0; zeroes-- {
                this.Double(this)
            }
        }

        index = abs(scalar[i])

        this.Double(this)
        p.Select(precomp[:], index)

        if scalar[i] > 0 {
            t.Add(this, &p)
        } else {
            t.Sub(this, &p)
        }

        this.x.Select(&p.x, nIsInfinityMask)
        this.y.Select(&p.y, nIsInfinityMask)
        this.z.Select(&p.z, nIsInfinityMask)

        pIsNoninfiniteMask = nonZeroToAllOnes(index)

        mask = pIsNoninfiniteMask & ^nIsInfinityMask

        this.x.Select(&t.x, mask)
        this.y.Select(&t.y, mask)
        this.z.Select(&t.z, mask)

        nIsInfinityMask &^= pIsNoninfiniteMask
    }

    if zeroes > 0 {
        for ; zeroes > 0; zeroes-- {
            this.Double(this)
        }
    }

    return this
}

// (x3, y3, z3) = (x1, y1, z1) + (x2, y2, z2)
// this = a + b
func (this *PointJacobian) Add(a, b *PointJacobian) *PointJacobian {
    var u1, u2, z22, z12, z23, z13 field.Element
    var s1, s2, h, h2, r, r2, tm field.Element

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

    r2.Square(&r)   // r2 = r ^ 2
    h2.Square(&h)   // h2 = h ^ 2

    tm.Mul(&h2, &h) // tm = h ^ 3
    this.x.Sub(&r2, &tm)
    tm.Mul(&u1, &h2)
    tm.Scalar(2)             // tm = 2 * (u1 * h ^ 2)
    this.x.Sub(&this.x, &tm) // x3 = r ^ 2 - h ^ 3 - 2 * u1 * h ^ 2

    tm.Mul(&u1, &h2)         // tm = u1 * h ^ 2
    tm.Sub(&tm, &this.x)     // tm = u1 * h ^ 2 - x3
    this.y.Mul(&r, &tm)
    tm.Mul(&h2, &h)          // tm = h ^ 3
    tm.Mul(&tm, &s1)         // tm = s1 * h ^ 3
    this.y.Sub(&this.y, &tm) // y3 = r * (u1 * h ^ 2 - x3) - s1 * h ^ 3

    this.z.Mul(&a.z, &b.z)
    this.z.Mul(&this.z, &h)  // z3 = z1 * z3 * h

    return this
}

// (x3, y3, z3) = (x1, y1, z1)- (x2, y2, z2)
// this = a + b
func (this *PointJacobian) Sub(a, b *PointJacobian) *PointJacobian {
    var u1, u2, z22, z12, z23, z13 field.Element
    var s1, s2, h, h2, r, r2, tm field.Element

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

    r2.Square(&r)   // r2 = r ^ 2
    h2.Square(&h)   // h2 = h ^ 2

    tm.Mul(&h2, &h) // tm = h ^ 3
    this.x.Sub(&r2, &tm)
    tm.Mul(&u1, &h2)
    tm.Scalar(2)    // tm = 2 * (u1 * h ^ 2)
    this.x.Sub(&this.x, &tm) // x3 = r ^ 2 - h ^ 3 - 2 * u1 * h ^ 2

    tm.Mul(&u1, &h2)         // tm = u1 * h ^ 2
    tm.Sub(&tm, &this.x)     // tm = u1 * h ^ 2 - x3
    this.y.Mul(&r, &tm)
    tm.Mul(&h2, &h)  // tm = h ^ 3
    tm.Mul(&tm, &s1) // tm = s1 * h ^ 3
    this.y.Sub(&this.y, &tm) // y3 = r * (u1 * h ^ 2 - x3) - s1 * h ^ 3

    this.z.Mul(&a.z, &b.z)
    this.z.Mul(&this.z, &h) // z3 = z1 * z3 * h

    return this
}

func (this *PointJacobian) Double(v *PointJacobian) *PointJacobian {
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
    y4.Scalar(8)      // y4 = 8 * y ^ 4

    s.Mul(&v.x, &y2)
    s.Scalar(4) // s = 4 * x * y ^ 2

    a.Set(&A)

    m.Dup(&x2)
    m.Scalar(3)
    az4.Mul(&a, &z4)
    m.Add(&m, &az4) // m = 3 * x ^ 2 + a * z ^ 4

    m2.Square(&m)   // m2 = m ^ 2

    this.z.Add(&v.y, &v.z)
    this.z.Square(&this.z)
    this.z.Sub(&this.z, &z2)
    this.z.Sub(&this.z, &y2) // z' = (y + z) ^2 - z ^ 2 - y ^ 2

    this.x.Sub(&m2, &s)
    this.x.Sub(&this.x, &s)  // x' = m2 - 2 * s

    this.y.Sub(&s, &this.x)
    this.y.Mul(&this.y, &m)
    this.y.Sub(&this.y, &y4) // y' = m * (s - x') - 8 * y ^ 4

    return this
}
