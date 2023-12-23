// Package bn256 implements a particular bilinear group.
//
// Bilinear groups are the basis of many of the new cryptographic protocols that
// have been proposed over the past decade. They consist of a triplet of groups
// (G₁, G₂ and GT) such that there exists a function e(g₁ˣ,g₂ʸ)=gTˣʸ (where gₓ
// is a generator of the respective group). That function is called a pairing
// function.
//
// This package specifically implements the Optimal Ate pairing over a 256-bit
// Barreto-Naehrig curve as described in
// http://cryptojedi.org/papers/dclxvi-20100714.pdf. Its output is compatible
// with the implementation described in that paper.
//
// This package previously claimed to operate at a 128-bit security level.
// However, recent improvements in attacks mean that is no longer true. See
// https://moderncrypto.org/mail-archive/curves/2016/000740.html.
package sm9curve

import (
    "io"
    "errors"
    "math/big"
    "crypto/rand"
)

var zero = newGFp(0)
var one = newGFp(1)
var two = newGFp(2)

func randomK(r io.Reader) (k *big.Int, err error) {
    for {
        k, err = rand.Int(r, Order)
        if k.Sign() > 0 || err != nil {
            return
        }
    }

    return
}

// G1 is an abstract cyclic group. The zero value is suitable for use as the
// output of an operation, but cannot be used as an input.
type G1 struct {
    p *curvePoint
}

//Gen1 is the generator of G1.
var Gen1 = &G1{curveGen}

// RandomG1 returns x and g₁ˣ where x is a random, non-zero number read from r.
func RandomG1(r io.Reader) (*big.Int, *G1, error) {
    k, err := randomK(r)
    if err != nil {
        return nil, nil, err
    }

    return k, new(G1).ScalarBaseMult(k), nil
}

func (g *G1) String() string {
    return "bn256.G1" + g.p.String()
}

// ScalarBaseMult sets e to g*k where g is the generator of the group and then
// returns e.
func (e *G1) ScalarBaseMult(k *big.Int) *G1 {
    if e.p == nil {
        e.p = &curvePoint{}
    }
    e.p.Mul(curveGen, k)
    return e
}

// ScalarMult sets e to a*k and then returns e.
func (e *G1) ScalarMult(a *G1, k *big.Int) *G1 {
    if e.p == nil {
        e.p = &curvePoint{}
    }
    e.p.Mul(a.p, k)
    return e
}

// Add sets e to a+b and then returns e.
func (e *G1) Add(a, b *G1) *G1 {
    if e.p == nil {
        e.p = &curvePoint{}
    }
    e.p.Add(a.p, b.p)
    return e
}

// Neg sets e to -a and then returns e.
func (e *G1) Neg(a *G1) *G1 {
    if e.p == nil {
        e.p = &curvePoint{}
    }
    e.p.Neg(a.p)
    return e
}

// Set sets e to a and then returns e.
func (e *G1) Set(a *G1) *G1 {
    if e.p == nil {
        e.p = &curvePoint{}
    }
    e.p.Set(a.p)
    return e
}

func (e *G1) Equal(x *G1) bool {
    if e.p == nil && x.p == nil {
        return true
    }

    return e.p.Equal(x.p)
}

// Marshal converts e to a byte slice.
func (e *G1) Marshal() []byte {
    // Each value is a 256-bit number.
    const numBytes = 256 / 8

    if e.p == nil {
        e.p = &curvePoint{}
    }

    ret := make([]byte, numBytes*2+1)
    ret[0] = 4

    e.p.MakeAffine()
    if e.p.IsInfinity() {
        return ret
    }
    temp := &gfP{}

    montDecode(temp, &e.p.x)
    temp.Marshal(ret[1:])
    montDecode(temp, &e.p.y)
    temp.Marshal(ret[1+numBytes:])

    return ret
}

// Unmarshal sets e to the result of converting the output of Marshal back into
// a group element and then returns e.
func (e *G1) Unmarshal(m []byte) ([]byte, error) {
    // Each value is a 256-bit number.
    const numBytes = 256 / 8

    if len(m) < 2*numBytes+1 {
        return nil, errors.New("bn256: not enough data")
    }

    if e.p == nil {
        e.p = &curvePoint{}
    } else {
        e.p.x, e.p.y = gfP{0}, gfP{0}
    }

    e.p.x.Unmarshal(m[1:])
    e.p.y.Unmarshal(m[1+numBytes:])
    montEncode(&e.p.x, &e.p.x)
    montEncode(&e.p.y, &e.p.y)

    zero := gfP{0}
    if e.p.x == zero && e.p.y == zero {
        // This is the point at infinity.
        e.p.y = *newGFp(1)
        e.p.z = gfP{0}
        e.p.t = gfP{0}
    } else {
        e.p.z = *newGFp(1)
        e.p.t = *newGFp(1)

        if !e.p.IsOnCurve() {
            return nil, errors.New("bn256: malformed point")
        }
    }

    return m[1+2*numBytes:], nil
}

// MarshalCompressed converts e to a byte slice with compress prefix.
// If the point is not on the curve (or is the conventional point at infinity), the behavior is undefined.
func (e *G1) MarshalCompressed() []byte {
    // Each value is a 256-bit number.
    const numBytes = 256 / 8
    ret := make([]byte, numBytes)
    if e.p == nil {
        e.p = &curvePoint{}
    }

    e.p.MakeAffine()
    temp := &gfP{}
    montDecode(temp, &e.p.y)

    temp.Marshal(ret[1:])
    ret[0] = (ret[numBytes] & 1) | 2
    montDecode(temp, &e.p.x)
    temp.Marshal(ret[1:])

    return ret
}

// UnmarshalCompressed sets e to the result of converting the output of Marshal back into
// a group element and then returns e.
func (e *G1) UnmarshalCompressed(data []byte) ([]byte, error) {
    // Each value is a 256-bit number.
    const numBytes = 256 / 8

    if len(data) < 1+numBytes {
        return nil, errors.New("sm9.G1: not enough data")
    }

    if data[0] != 2 && data[0] != 3 { // compressed form
        return nil, errors.New("sm9.G1: invalid point compress byte")
    }

    if e.p == nil {
        e.p = &curvePoint{}
    } else {
        e.p.x.Set(zero)
        e.p.y.Set(zero)
    }

    e.p.x.Unmarshal(data[1:])
    montEncode(&e.p.x, &e.p.x)

    x3 := e.p.polynomial(&e.p.x)
    e.p.y.Sqrt(x3)
    montDecode(x3, &e.p.y)

    if byte(x3[0]&1) != data[0]&1 {
        gfpNeg(&e.p.y, &e.p.y)
    }

    if e.p.x.Equal(zero) == 1 && e.p.y.Equal(zero) == 1 {
        // This is the point at infinity.
        e.p.SetInfinity()
    } else {
        e.p.z.Set(one)
        e.p.t.Set(one)

        if !e.p.IsOnCurve() {
            return nil, errors.New("sm9.G1: malformed point")
        }
    }

    return data[numBytes+1:], nil
}

// G2 is an abstract cyclic group. The zero value is suitable for use as the
// output of an operation, but cannot be used as an input.
type G2 struct {
    p *twistPoint
}

//Gen2 is the generator of G2.
var Gen2 = &G2{twistGen}

// RandomG2 returns x and g₂ˣ where x is a random, non-zero number read from r.
func RandomG2(r io.Reader) (*big.Int, *G2, error) {
    k, err := randomK(r)
    if err != nil {
        return nil, nil, err
    }

    return k, new(G2).ScalarBaseMult(k), nil
}

func (e *G2) String() string {
    return "bn256.G2" + e.p.String()
}

// ScalarBaseMult sets e to g*k where g is the generator of the group and then
// returns out.
func (e *G2) ScalarBaseMult(k *big.Int) *G2 {
    if e.p == nil {
        e.p = &twistPoint{}
    }
    e.p.Mul(twistGen, k)
    return e
}

// ScalarMult sets e to a*k and then returns e.
func (e *G2) ScalarMult(a *G2, k *big.Int) *G2 {
    if e.p == nil {
        e.p = &twistPoint{}
    }
    e.p.Mul(a.p, k)
    return e
}

// Add sets e to a+b and then returns e.
func (e *G2) Add(a, b *G2) *G2 {
    if e.p == nil {
        e.p = &twistPoint{}
    }
    e.p.Add(a.p, b.p)
    return e
}

// Neg sets e to -a and then returns e.
func (e *G2) Neg(a *G2) *G2 {
    if e.p == nil {
        e.p = &twistPoint{}
    }
    e.p.Neg(a.p)
    return e
}

// Set sets e to a and then returns e.
func (e *G2) Set(a *G2) *G2 {
    if e.p == nil {
        e.p = &twistPoint{}
    }
    e.p.Set(a.p)
    return e
}

func (e *G2) Equal(x *G2) bool {
    if e.p == nil && x.p == nil {
        return true
    }

    return e.p.Equal(x.p)
}

// Marshal converts e into a byte slice.
func (e *G2) Marshal() []byte {
    // Each value is a 256-bit number.
    const numBytes = 256 / 8

    if e.p == nil {
        e.p = &twistPoint{}
    }

    e.p.MakeAffine()
    if e.p.IsInfinity() {
        return make([]byte, 1)
    }

    ret := make([]byte, 1+numBytes*4)
    ret[0] = 0x04
    temp := &gfP{}

    montDecode(temp, &e.p.x.x)
    temp.Marshal(ret[1:])
    montDecode(temp, &e.p.x.y)
    temp.Marshal(ret[1+numBytes:])
    montDecode(temp, &e.p.y.x)
    temp.Marshal(ret[1+2*numBytes:])
    montDecode(temp, &e.p.y.y)
    temp.Marshal(ret[1+3*numBytes:])

    return ret
}

// Unmarshal sets e to the result of converting the output of Marshal back into
// a group element and then returns e.
func (e *G2) Unmarshal(m []byte) ([]byte, error) {
    // Each value is a 256-bit number.
    const numBytes = 256 / 8

    if e.p == nil {
        e.p = &twistPoint{}
    }

    if len(m) > 0 && m[0] == 0x00 {
        e.p.SetInfinity()
        return m[1:], nil
    } else if len(m) > 0 && m[0] != 0x04 {
        return nil, errors.New("bn256: malformed point")
    } else if len(m) < 1+4*numBytes {
        return nil, errors.New("bn256: not enough data")
    }

    e.p.x.x.Unmarshal(m[1:])
    e.p.x.y.Unmarshal(m[1+numBytes:])
    e.p.y.x.Unmarshal(m[1+2*numBytes:])
    e.p.y.y.Unmarshal(m[1+3*numBytes:])

    montEncode(&e.p.x.x, &e.p.x.x)
    montEncode(&e.p.x.y, &e.p.x.y)
    montEncode(&e.p.y.x, &e.p.y.x)
    montEncode(&e.p.y.y, &e.p.y.y)

    if e.p.x.IsZero() && e.p.y.IsZero() {
        // This is the point at infinity.
        e.p.y.SetOne()
        e.p.z.SetZero()
        e.p.t.SetZero()
    } else {
        e.p.z.SetOne()
        e.p.t.SetOne()

        if !e.p.IsOnCurve() {
            return nil, errors.New("bn256: malformed point")
        }
    }

    return m[1+4*numBytes:], nil
}

// GT is an abstract cyclic group. The zero value is suitable for use as the
// output of an operation, but cannot be used as an input.
type GT struct {
    p *gfP12
}

// RandomGT returns x and e(g₁, g₂)ˣ where x is a random, non-zero number read
// from r.
func RandomGT(r io.Reader) (*big.Int, *GT, error) {
    k, err := randomK(r)
    if err != nil {
        return nil, nil, err
    }

    return k, new(GT).ScalarBaseMult(k), nil
}

// Pair calculates an Optimal Ate pairing.
func Pair(g1 *G1, g2 *G2) *GT {
    g := optimalAte(g2.p, g1.p)
    return &GT{g}
}

// Miller applies Miller's algorithm, which is a bilinear function from the
// source groups to F_p^12. Miller(g1, g2).Finalize() is equivalent to Pair(g1,
// g2).
func Miller(g1 *G1, g2 *G2) *GT {
    return &GT{miller(g2.p, g1.p)}
}

func (g *GT) String() string {
    der := montDecodeGfp12(*g.p)
    return "bn256.GT" + der.String()
}

// ScalarBaseMult sets e to g*k where g is the generator of the group and then
// returns out.
func (e *GT) ScalarBaseMult(k *big.Int) *GT {
    if e.p == nil {
        e.p = &gfP12{}
    }
    e.p.Exp(gfP12Gen, k)
    return e
}

// ScalarMult sets e to a*k and then returns e.
func (e *GT) ScalarMult(a *GT, k *big.Int) *GT {
    if e.p == nil {
        e.p = &gfP12{}
    }
    e.p.Exp(a.p, k)
    return e
}

// Add sets e to a+b and then returns e.
func (e *GT) Add(a, b *GT) *GT {
    if e.p == nil {
        e.p = &gfP12{}
    }
    e.p.Mul(a.p, b.p)
    return e
}

// Neg sets e to -a and then returns e.
func (e *GT) Neg(a *GT) *GT {
    if e.p == nil {
        e.p = &gfP12{}
    }
    e.p.Conjugate(a.p)
    return e
}

// Set sets e to a and then returns e.
func (e *GT) Set(a *GT) *GT {
    if e.p == nil {
        e.p = &gfP12{}
    }
    e.p.Set(a.p)
    return e
}

// Finalize is a linear function from F_p^12 to GT.
func (e *GT) Finalize() *GT {
    ret := finalExponentiation(e.p)
    e.p.Set(ret)
    return e
}

// Marshal converts e into a byte slice.
func (e *GT) Marshal() []byte {
    // Each value is a 256-bit number.
    const numBytes = 256 / 8

    if e.p == nil {
        e.p = &gfP12{}
        e.p.SetOne()
    }

    ret := make([]byte, numBytes*12)
    temp := &gfP{}

    montDecode(temp, &e.p.x.x.x)
    temp.Marshal(ret)
    montDecode(temp, &e.p.x.x.y)
    temp.Marshal(ret[numBytes:])
    montDecode(temp, &e.p.x.y.x)
    temp.Marshal(ret[2*numBytes:])
    montDecode(temp, &e.p.x.y.y)
    temp.Marshal(ret[3*numBytes:])
    montDecode(temp, &e.p.x.z.x)
    temp.Marshal(ret[4*numBytes:])
    montDecode(temp, &e.p.x.z.y)
    temp.Marshal(ret[5*numBytes:])
    montDecode(temp, &e.p.y.x.x)
    temp.Marshal(ret[6*numBytes:])
    montDecode(temp, &e.p.y.x.y)
    temp.Marshal(ret[7*numBytes:])
    montDecode(temp, &e.p.y.y.x)
    temp.Marshal(ret[8*numBytes:])
    montDecode(temp, &e.p.y.y.y)
    temp.Marshal(ret[9*numBytes:])
    montDecode(temp, &e.p.y.z.x)
    temp.Marshal(ret[10*numBytes:])
    montDecode(temp, &e.p.y.z.y)
    temp.Marshal(ret[11*numBytes:])

    return ret
}

// Unmarshal sets e to the result of converting the output of Marshal back into
// a group element and then returns e.
func (e *GT) Unmarshal(m []byte) ([]byte, error) {
    // Each value is a 256-bit number.
    const numBytes = 256 / 8

    if len(m) < 12*numBytes {
        return nil, errors.New("bn256: not enough data")
    }

    if e.p == nil {
        e.p = &gfP12{}
    }

    e.p.x.x.x.Unmarshal(m)
    e.p.x.x.y.Unmarshal(m[numBytes:])
    e.p.x.y.x.Unmarshal(m[2*numBytes:])
    e.p.x.y.y.Unmarshal(m[3*numBytes:])
    e.p.x.z.x.Unmarshal(m[4*numBytes:])
    e.p.x.z.y.Unmarshal(m[5*numBytes:])
    e.p.y.x.x.Unmarshal(m[6*numBytes:])
    e.p.y.x.y.Unmarshal(m[7*numBytes:])
    e.p.y.y.x.Unmarshal(m[8*numBytes:])
    e.p.y.y.y.Unmarshal(m[9*numBytes:])
    e.p.y.z.x.Unmarshal(m[10*numBytes:])
    e.p.y.z.y.Unmarshal(m[11*numBytes:])
    montEncode(&e.p.x.x.x, &e.p.x.x.x)
    montEncode(&e.p.x.x.y, &e.p.x.x.y)
    montEncode(&e.p.x.y.x, &e.p.x.y.x)
    montEncode(&e.p.x.y.y, &e.p.x.y.y)
    montEncode(&e.p.x.z.x, &e.p.x.z.x)
    montEncode(&e.p.x.z.y, &e.p.x.z.y)
    montEncode(&e.p.y.x.x, &e.p.y.x.x)
    montEncode(&e.p.y.x.y, &e.p.y.x.y)
    montEncode(&e.p.y.y.x, &e.p.y.y.x)
    montEncode(&e.p.y.y.y, &e.p.y.y.y)
    montEncode(&e.p.y.z.x, &e.p.y.z.x)
    montEncode(&e.p.y.z.y, &e.p.y.z.y)

    return m[12*numBytes:], nil
}

// MarshalCompressed converts e into a byte slice with uncompressed point prefix
func (e *G2) MarshalCompressed() []byte {
    // Each value is a 256-bit number.
    const numBytes = 256 / 8
    ret := make([]byte, numBytes*2+1)
    if e.p == nil {
        e.p = &twistPoint{}
    }
    e.p.MakeAffine()
    temp := &gfP{}
    montDecode(temp, &e.p.y.y)
    temp.Marshal(ret[1:])
    ret[0] = (ret[numBytes] & 1) | 2

    montDecode(temp, &e.p.x.x)
    temp.Marshal(ret[1:])
    montDecode(temp, &e.p.x.y)
    temp.Marshal(ret[numBytes+1:])

    return ret
}

// UnmarshalCompressed sets e to the result of converting the output of Marshal back into
// a group element and then returns e.
func (e *G2) UnmarshalCompressed(data []byte) ([]byte, error) {
    // Each value is a 256-bit number.
    const numBytes = 256 / 8
    if len(data) < 1+2*numBytes {
        return nil, errors.New("sm9.G2: not enough data")
    }
    if data[0] != 2 && data[0] != 3 { // compressed form
        return nil, errors.New("sm9.G2: invalid point compress byte")
    }

    // Unmarshal the points and check their caps
    if e.p == nil {
        e.p = &twistPoint{}
    }

    e.p.x.x.Unmarshal(data[1:])
    e.p.x.y.Unmarshal(data[1+numBytes:])

    montEncode(&e.p.x.x, &e.p.x.x)
    montEncode(&e.p.x.y, &e.p.x.y)
    x3 := e.p.polynomial(&e.p.x)
    e.p.y.Sqrt(x3)
    x3y := &gfP{}
    montDecode(x3y, &e.p.y.y)
    if byte(x3y[0]&1) != data[0]&1 {
        e.p.y.Neg(&e.p.y)
    }

    if e.p.x.IsZero() && e.p.y.IsZero() {
        // This is the point at infinity.
        e.p.y.SetOne()
        e.p.z.SetZero()
        e.p.t.SetZero()
    } else {
        e.p.z.SetOne()
        e.p.t.SetOne()

        if !e.p.IsOnCurve() {
            return nil, errors.New("sm9.G2: malformed point")
        }
    }
    return data[1+2*numBytes:], nil
}

func (e *G2) fillBytes(buffer []byte) {
    // Each value is a 256-bit number.
    const numBytes = 256 / 8

    if e.p == nil {
        e.p = &twistPoint{}
    }

    e.p.MakeAffine()
    if e.p.IsInfinity() {
        return
    }
    temp := &gfP{}

    montDecode(temp, &e.p.x.x)
    temp.Marshal(buffer)
    montDecode(temp, &e.p.x.y)
    temp.Marshal(buffer[numBytes:])
    montDecode(temp, &e.p.y.x)
    temp.Marshal(buffer[2*numBytes:])
    montDecode(temp, &e.p.y.y)
    temp.Marshal(buffer[3*numBytes:])
}

func NormalizeScalar(scalar []byte) []byte {
    if len(scalar) == 32 {
        return scalar
    }

    s := new(big.Int).SetBytes(scalar)
    if len(scalar) > 32 {
        s.Mod(s, Order)
    }

    out := make([]byte, 32)

    return s.FillBytes(out)
}
