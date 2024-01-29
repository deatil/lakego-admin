package field

// Invert sets e = 1/x, and returns e.
//
// If x == 0, Invert returns e = 0.
func (e *Element) Invert(x *Element) *Element {
    // Inversion is implemented as exponentiation with exponent p − 2.
    // The sequence of 14 multiplications and 255 squarings is derived from the
    // following addition chain generated with github.com/mmcloughlin/addchain v0.4.0.
    //
    //	_10      = 2*1
    //	_11      = 1 + _10
    //	_110     = 2*_11
    //	_111     = 1 + _110
    //	_111000  = _111 << 3
    //	_111111  = _111 + _111000
    //	_1111110 = 2*_111111
    //	_1111111 = 1 + _1111110
    //	x12      = _1111110 << 5 + _111111
    //	x24      = x12 << 12 + x12
    //	x31      = x24 << 7 + _1111111
    //	i39      = x31 << 2
    //	i68      = i39 << 29
    //	x62      = x31 + i68
    //	i71      = i68 << 2
    //	x64      = i39 + i71 + _11
    //	i265     = ((i71 << 32 + x64) << 64 + x64) << 94
    //	return     (x62 + i265) << 2 + 1
    //
    var z = new(Element).Set(e)
    var t0 = new(Element)
    var t1 = new(Element)
    var t2 = new(Element)

    z.Square(x)
    t0.Mul(x, z)
    z.Square(t0)
    z.Mul(x, z)
    t1.Square(z)
    for s := 1; s < 3; s++ {
        t1.Square(t1)
    }
    t1.Mul(z, t1)
    t2.Square(t1)
    z.Mul(x, t2)
    for s := 0; s < 5; s++ {
        t2.Square(t2)
    }
    t1.Mul(t1, t2)
    t2.Square(t1)
    for s := 1; s < 12; s++ {
        t2.Square(t2)
    }
    t1.Mul(t1, t2)
    for s := 0; s < 7; s++ {
        t1.Square(t1)
    }
    z.Mul(z, t1)
    t2.Square(z)
    for s := 1; s < 2; s++ {
        t2.Square(t2)
    }
    t1.Square(t2)
    for s := 1; s < 29; s++ {
        t1.Square(t1)
    }
    z.Mul(z, t1)
    for s := 0; s < 2; s++ {
        t1.Square(t1)
    }
    t2.Mul(t2, t1)
    t0.Mul(t0, t2)
    for s := 0; s < 32; s++ {
        t1.Square(t1)
    }
    t1.Mul(t0, t1)
    for s := 0; s < 64; s++ {
        t1.Square(t1)
    }
    t0.Mul(t0, t1)
    for s := 0; s < 94; s++ {
        t0.Square(t0)
    }
    z.Mul(z, t0)
    for s := 0; s < 2; s++ {
        z.Square(z)
    }
    z.Mul(x, z)
    return e.Set(z)
}
