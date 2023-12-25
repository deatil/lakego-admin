package sm9curve

// Invert sets e = 1/x, and returns e.
//
// If x == 0, Invert returns e = 0.
func (e *gfP) Invert(x *gfP) *gfP {
    // Inversion is implemented as exponentiation with exponent p − 2.
    // The sequence of 56 multiplications and 250 squarings is derived from the
    // following addition chain generated with github.com/mmcloughlin/addchain v0.4.0.
    //
    //	_10       = 2*1
    //	_100      = 2*_10
    //	_110      = _10 + _100
    //	_1010     = _100 + _110
    //	_1011     = 1 + _1010
    //	_1101     = _10 + _1011
    //	_10000    = _110 + _1010
    //	_10101    = _1010 + _1011
    //	_11011    = _110 + _10101
    //	_11101    = _10 + _11011
    //	_11111    = _10 + _11101
    //	_101001   = _1010 + _11111
    //	_101011   = _10 + _101001
    //	_111011   = _10000 + _101011
    //	_1000101  = _1010 + _111011
    //	_1001111  = _1010 + _1000101
    //	_1010001  = _10 + _1001111
    //	_1011011  = _1010 + _1010001
    //	_1011101  = _10 + _1011011
    //	_1011111  = _10 + _1011101
    //	_1100011  = _100 + _1011111
    //	_1101001  = _110 + _1100011
    //	_1101101  = _100 + _1101001
    //	_1101111  = _10 + _1101101
    //	_1110101  = _110 + _1101111
    //	_1111011  = _110 + _1110101
    //	_10110110 = _111011 + _1111011
    //	i72       = ((_10110110 << 2 + 1) << 33 + _10101) << 8
    //	i94       = ((_11101 + i72) << 9 + _1101111) << 10 + _1110101
    //	i116      = ((2*i94 + 1) << 14 + _1110101) << 5
    //	i129      = 2*((_1101 + i116) << 9 + _1111011 + _100)
    //	i146      = ((1 + i129) << 5 + _1011) << 9 + _111011
    //	i174      = ((i146 << 8 + _11101) << 9 + _101001) << 9
    //	i194      = ((_11111 + i174) << 8 + _101001) << 9 + _1101001
    //	i220      = ((i194 << 8 + _1100011) << 8 + _1001111) << 8
    //	i237      = ((_1011101 + i220) << 7 + _1101101) << 7 + _1011111
    //	i260      = ((i237 << 8 + _101011) << 6 + _11111) << 7
    //	i279      = ((_11011 + i260) << 9 + _1001111) << 7 + _1100011
    //	i305      = ((i279 << 8 + _1010001) << 8 + _1000101) << 8
    //	return      _1111011 + i305
    //
    var z = new(gfP).Set(e)
    var t0 = new(gfP)
    var t1 = new(gfP)
    var t2 = new(gfP)
    var t3 = new(gfP)
    var t4 = new(gfP)
    var t5 = new(gfP)
    var t6 = new(gfP)
    var t7 = new(gfP)
    var t8 = new(gfP)
    var t9 = new(gfP)
    var t10 = new(gfP)
    var t11 = new(gfP)
    var t12 = new(gfP)
    var t13 = new(gfP)
    var t14 = new(gfP)
    var t15 = new(gfP)
    var t16 = new(gfP)
    var t17 = new(gfP)
    var t18 = new(gfP)
    var t19 = new(gfP)
    var t20 = new(gfP)

    t17.Square(x)
    t15.Square(t17)
    z.Mul(t17, t15)
    t2.Mul(t15, z)
    t14.Mul(x, t2)
    t16.Mul(t17, t14)
    t0.Mul(z, t2)
    t19.Mul(t2, t14)
    t4.Mul(z, t19)
    t12.Mul(t17, t4)
    t5.Mul(t17, t12)
    t11.Mul(t2, t5)
    t6.Mul(t17, t11)
    t13.Mul(t0, t6)
    t0.Mul(t2, t13)
    t3.Mul(t2, t0)
    t1.Mul(t17, t3)
    t2.Mul(t2, t1)
    t9.Mul(t17, t2)
    t7.Mul(t17, t9)
    t2.Mul(t15, t7)
    t10.Mul(z, t2)
    t8.Mul(t15, t10)
    t18.Mul(t17, t8)
    t17.Mul(z, t18)
    z.Mul(z, t17)
    t20.Mul(t13, z)
    for s := 0; s < 2; s++ {
        t20.Square(t20)
    }
    t20.Mul(x, t20)
    for s := 0; s < 33; s++ {
        t20.Square(t20)
    }
    t19.Mul(t19, t20)
    for s := 0; s < 8; s++ {
        t19.Square(t19)
    }
    t19.Mul(t12, t19)
    for s := 0; s < 9; s++ {
        t19.Square(t19)
    }
    t18.Mul(t18, t19)
    for s := 0; s < 10; s++ {
        t18.Square(t18)
    }
    t18.Mul(t17, t18)
    t18.Square(t18)
    t18.Mul(x, t18)
    for s := 0; s < 14; s++ {
        t18.Square(t18)
    }
    t17.Mul(t17, t18)
    for s := 0; s < 5; s++ {
        t17.Square(t17)
    }
    t16.Mul(t16, t17)
    for s := 0; s < 9; s++ {
        t16.Square(t16)
    }
    t16.Mul(z, t16)
    t15.Mul(t15, t16)
    t15.Square(t15)
    t15.Mul(x, t15)
    for s := 0; s < 5; s++ {
        t15.Square(t15)
    }
    t14.Mul(t14, t15)
    for s := 0; s < 9; s++ {
        t14.Square(t14)
    }
    t13.Mul(t13, t14)
    for s := 0; s < 8; s++ {
        t13.Square(t13)
    }
    t12.Mul(t12, t13)
    for s := 0; s < 9; s++ {
        t12.Square(t12)
    }
    t12.Mul(t11, t12)
    for s := 0; s < 9; s++ {
        t12.Square(t12)
    }
    t12.Mul(t5, t12)
    for s := 0; s < 8; s++ {
        t12.Square(t12)
    }
    t11.Mul(t11, t12)
    for s := 0; s < 9; s++ {
        t11.Square(t11)
    }
    t10.Mul(t10, t11)
    for s := 0; s < 8; s++ {
        t10.Square(t10)
    }
    t10.Mul(t2, t10)
    for s := 0; s < 8; s++ {
        t10.Square(t10)
    }
    t10.Mul(t3, t10)
    for s := 0; s < 8; s++ {
        t10.Square(t10)
    }
    t9.Mul(t9, t10)
    for s := 0; s < 7; s++ {
        t9.Square(t9)
    }
    t8.Mul(t8, t9)
    for s := 0; s < 7; s++ {
        t8.Square(t8)
    }
    t7.Mul(t7, t8)
    for s := 0; s < 8; s++ {
        t7.Square(t7)
    }
    t6.Mul(t6, t7)
    for s := 0; s < 6; s++ {
        t6.Square(t6)
    }
    t5.Mul(t5, t6)
    for s := 0; s < 7; s++ {
        t5.Square(t5)
    }
    t4.Mul(t4, t5)
    for s := 0; s < 9; s++ {
        t4.Square(t4)
    }
    t3.Mul(t3, t4)
    for s := 0; s < 7; s++ {
        t3.Square(t3)
    }
    t2.Mul(t2, t3)
    for s := 0; s < 8; s++ {
        t2.Square(t2)
    }
    t1.Mul(t1, t2)
    for s := 0; s < 8; s++ {
        t1.Square(t1)
    }
    t0.Mul(t0, t1)
    for s := 0; s < 8; s++ {
        t0.Square(t0)
    }
    z.Mul(z, t0)
    return e.Set(z)
}

// Sqrt sets e to a square root of x. If x is not a square, Sqrt returns
// false and e is unchanged. e and x can overlap.
func Sqrt(e, x *gfP) (isSquare bool) {
    candidate, b, i := &gfP{}, &gfP{}, &gfP{}
    sqrtCandidate(candidate, x)
    gfpMul(b, twoExpPMinus5Over8, candidate) // b=ta1
    gfpMul(candidate, x, b)                  // a1=fb
    gfpMul(i, two, candidate)                // i=2(fb)
    gfpMul(i, i, b)                          // i=2(fb)b
    gfpSub(i, i, one)                        // i=2(fb)b-1
    gfpMul(i, candidate, i)                  // i=(fb)(2(fb)b-1)
    square := new(gfP).Square(i)
    if square.Equal(x) != 1 {
        return false
    }
    e.Set(i)
    return true
}

// sqrtCandidate sets z to a square root candidate for x. z and x must not overlap.
func sqrtCandidate(z, x *gfP) {
    // Since p = 8k+5, exponentiation by (p - 5) / 8 yields a square root candidate.
    //
    // The sequence of 54 multiplications and 248 squarings is derived from the
    // following addition chain generated with github.com/mmcloughlin/addchain v0.4.0.
    //
    //	_10      = 2*1
    //	_100     = 2*_10
    //	_110     = _10 + _100
    //	_1010    = _100 + _110
    //	_1011    = 1 + _1010
    //	_1101    = _10 + _1011
    //	_1111    = _10 + _1101
    //	_10000   = 1 + _1111
    //	_10101   = _110 + _1111
    //	_11011   = _110 + _10101
    //	_11101   = _10 + _11011
    //	_11111   = _10 + _11101
    //	_101001  = _1010 + _11111
    //	_101011  = _10 + _101001
    //	_111011  = _10000 + _101011
    //	_1000101 = _1010 + _111011
    //	_1001111 = _1010 + _1000101
    //	_1010001 = _10 + _1001111
    //	_1011011 = _1010 + _1010001
    //	_1011101 = _10 + _1011011
    //	_1011111 = _10 + _1011101
    //	_1100011 = _100 + _1011111
    //	_1101001 = _110 + _1100011
    //	_1101101 = _100 + _1101001
    //	_1101111 = _10 + _1101101
    //	_1110101 = _110 + _1101111
    //	i72      = ((_1011011 << 3 + 1) << 33 + _10101) << 8
    //	i94      = ((_11101 + i72) << 9 + _1101111) << 10 + _1110101
    //	i116     = ((2*i94 + 1) << 14 + _1110101) << 5
    //	i129     = 2*((_1101 + i116) << 9 + _1110101) + _10101
    //	i153     = ((i129 << 5 + _1011) << 9 + _111011) << 8
    //	i174     = ((_11101 + i153) << 9 + _101001) << 9 + _11111
    //	i201     = ((i174 << 8 + _101001) << 9 + _1101001) << 8
    //	i220     = ((_1100011 + i201) << 8 + _1001111) << 8 + _1011101
    //	i244     = ((i220 << 7 + _1101101) << 7 + _1011111) << 8
    //	i260     = ((_101011 + i244) << 6 + _11111) << 7 + _11011
    //	i286     = ((i260 << 9 + _1001111) << 7 + _1100011) << 8
    //	return     ((_1010001 + i286) << 8 + _1000101) << 5 + _1111
    //
    var t0 = new(gfP)
    var t1 = new(gfP)
    var t2 = new(gfP)
    var t3 = new(gfP)
    var t4 = new(gfP)
    var t5 = new(gfP)
    var t6 = new(gfP)
    var t7 = new(gfP)
    var t8 = new(gfP)
    var t9 = new(gfP)
    var t10 = new(gfP)
    var t11 = new(gfP)
    var t12 = new(gfP)
    var t13 = new(gfP)
    var t14 = new(gfP)
    var t15 = new(gfP)
    var t16 = new(gfP)
    var t17 = new(gfP)
    var t18 = new(gfP)
    var t19 = new(gfP)

    t18.Square(x)
    t8.Square(t18)
    t16.Mul(t18, t8)
    t2.Mul(t8, t16)
    t14.Mul(x, t2)
    t17.Mul(t18, t14)
    z.Mul(t18, t17)
    t0.Mul(x, z)
    t15.Mul(t16, z)
    t4.Mul(t16, t15)
    t12.Mul(t18, t4)
    t5.Mul(t18, t12)
    t11.Mul(t2, t5)
    t6.Mul(t18, t11)
    t13.Mul(t0, t6)
    t0.Mul(t2, t13)
    t3.Mul(t2, t0)
    t1.Mul(t18, t3)
    t19.Mul(t2, t1)
    t9.Mul(t18, t19)
    t7.Mul(t18, t9)
    t2.Mul(t8, t7)
    t10.Mul(t16, t2)
    t8.Mul(t8, t10)
    t18.Mul(t18, t8)
    t16.Mul(t16, t18)
    for s := 0; s < 3; s++ {
        t19.Square(t19)
    }
    t19.Mul(x, t19)
    for s := 0; s < 33; s++ {
        t19.Square(t19)
    }
    t19.Mul(t15, t19)
    for s := 0; s < 8; s++ {
        t19.Square(t19)
    }
    t19.Mul(t12, t19)
    for s := 0; s < 9; s++ {
        t19.Square(t19)
    }
    t18.Mul(t18, t19)
    for s := 0; s < 10; s++ {
        t18.Square(t18)
    }
    t18.Mul(t16, t18)
    t18.Square(t18)
    t18.Mul(x, t18)
    for s := 0; s < 14; s++ {
        t18.Square(t18)
    }
    t18.Mul(t16, t18)
    for s := 0; s < 5; s++ {
        t18.Square(t18)
    }
    t17.Mul(t17, t18)
    for s := 0; s < 9; s++ {
        t17.Square(t17)
    }
    t16.Mul(t16, t17)
    t16.Square(t16)
    t15.Mul(t15, t16)
    for s := 0; s < 5; s++ {
        t15.Square(t15)
    }
    t14.Mul(t14, t15)
    for s := 0; s < 9; s++ {
        t14.Square(t14)
    }
    t13.Mul(t13, t14)
    for s := 0; s < 8; s++ {
        t13.Square(t13)
    }
    t12.Mul(t12, t13)
    for s := 0; s < 9; s++ {
        t12.Square(t12)
    }
    t12.Mul(t11, t12)
    for s := 0; s < 9; s++ {
        t12.Square(t12)
    }
    t12.Mul(t5, t12)
    for s := 0; s < 8; s++ {
        t12.Square(t12)
    }
    t11.Mul(t11, t12)
    for s := 0; s < 9; s++ {
        t11.Square(t11)
    }
    t10.Mul(t10, t11)
    for s := 0; s < 8; s++ {
        t10.Square(t10)
    }
    t10.Mul(t2, t10)
    for s := 0; s < 8; s++ {
        t10.Square(t10)
    }
    t10.Mul(t3, t10)
    for s := 0; s < 8; s++ {
        t10.Square(t10)
    }
    t9.Mul(t9, t10)
    for s := 0; s < 7; s++ {
        t9.Square(t9)
    }
    t8.Mul(t8, t9)
    for s := 0; s < 7; s++ {
        t8.Square(t8)
    }
    t7.Mul(t7, t8)
    for s := 0; s < 8; s++ {
        t7.Square(t7)
    }
    t6.Mul(t6, t7)
    for s := 0; s < 6; s++ {
        t6.Square(t6)
    }
    t5.Mul(t5, t6)
    for s := 0; s < 7; s++ {
        t5.Square(t5)
    }
    t4.Mul(t4, t5)
    for s := 0; s < 9; s++ {
        t4.Square(t4)
    }
    t3.Mul(t3, t4)
    for s := 0; s < 7; s++ {
        t3.Square(t3)
    }
    t2.Mul(t2, t3)
    for s := 0; s < 8; s++ {
        t2.Square(t2)
    }
    t1.Mul(t1, t2)
    for s := 0; s < 8; s++ {
        t1.Square(t1)
    }
    t0.Mul(t0, t1)
    for s := 0; s < 5; s++ {
        t0.Square(t0)
    }
    z.Mul(z, t0)
}
