package sm9curve

func (e *gfP2) expPMinus1Over4(x *gfP2) *gfP2 {
    // The sequence of 53 multiplications and 249 squarings is derived from the
    // following addition chain generated with github.com/mmcloughlin/addchain v0.4.0.
    //
    //	_10      = 2*1
    //	_100     = 2*_10
    //	_110     = _10 + _100
    //	_1010    = _100 + _110
    //	_1011    = 1 + _1010
    //	_1101    = _10 + _1011
    //	_10000   = _110 + _1010
    //	_10101   = _1010 + _1011
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
    //	i71      = ((_1011011 << 3 + 1) << 33 + _10101) << 8
    //	i93      = ((_11101 + i71) << 9 + _1101111) << 10 + _1110101
    //	i115     = ((2*i93 + 1) << 14 + _1110101) << 5
    //	i128     = 2*((_1101 + i115) << 9 + _1110101) + _10101
    //	i152     = ((i128 << 5 + _1011) << 9 + _111011) << 8
    //	i173     = ((_11101 + i152) << 9 + _101001) << 9 + _11111
    //	i200     = ((i173 << 8 + _101001) << 9 + _1101001) << 8
    //	i219     = ((_1100011 + i200) << 8 + _1001111) << 8 + _1011101
    //	i243     = ((i219 << 7 + _1101101) << 7 + _1011111) << 8
    //	i259     = ((_101011 + i243) << 6 + _11111) << 7 + _11011
    //	i285     = ((i259 << 9 + _1001111) << 7 + _1100011) << 8
    //	return     ((_1010001 + i285) << 8 + _1000101) << 6 + _11111
    //
    var z = new(gfP2).Set(e)
    var t0 = new(gfP2)
    var t1 = new(gfP2)
    var t2 = new(gfP2)
    var t3 = new(gfP2)
    var t4 = new(gfP2)
    var t5 = new(gfP2)
    var t6 = new(gfP2)
    var t7 = new(gfP2)
    var t8 = new(gfP2)
    var t9 = new(gfP2)
    var t10 = new(gfP2)
    var t11 = new(gfP2)
    var t12 = new(gfP2)
    var t13 = new(gfP2)
    var t14 = new(gfP2)
    var t15 = new(gfP2)
    var t16 = new(gfP2)
    var t17 = new(gfP2)
    var t18 = new(gfP2)

    t17.Square(x)
    t7.Square(t17)
    t15.Mul(t17, t7)
    t2.Mul(t7, t15)
    t13.Mul(x, t2)
    t16.Mul(t17, t13)
    t0.Mul(t15, t2)
    t14.Mul(t2, t13)
    t4.Mul(t15, t14)
    t11.Mul(t17, t4)
    z.Mul(t17, t11)
    t10.Mul(t2, z)
    t5.Mul(t17, t10)
    t12.Mul(t0, t5)
    t0.Mul(t2, t12)
    t3.Mul(t2, t0)
    t1.Mul(t17, t3)
    t18.Mul(t2, t1)
    t8.Mul(t17, t18)
    t6.Mul(t17, t8)
    t2.Mul(t7, t6)
    t9.Mul(t15, t2)
    t7.Mul(t7, t9)
    t17.Mul(t17, t7)
    t15.Mul(t15, t17)
    for s := 0; s < 3; s++ {
        t18.Square(t18)
    }
    t18.Mul(x, t18)
    for s := 0; s < 33; s++ {
        t18.Square(t18)
    }
    t18.Mul(t14, t18)
    for s := 0; s < 8; s++ {
        t18.Square(t18)
    }
    t18.Mul(t11, t18)
    for s := 0; s < 9; s++ {
        t18.Square(t18)
    }
    t17.Mul(t17, t18)
    for s := 0; s < 10; s++ {
        t17.Square(t17)
    }
    t17.Mul(t15, t17)
    t17.Square(t17)
    t17.Mul(x, t17)
    for s := 0; s < 14; s++ {
        t17.Square(t17)
    }
    t17.Mul(t15, t17)
    for s := 0; s < 5; s++ {
        t17.Square(t17)
    }
    t16.Mul(t16, t17)
    for s := 0; s < 9; s++ {
        t16.Square(t16)
    }
    t15.Mul(t15, t16)
    t15.Square(t15)
    t14.Mul(t14, t15)
    for s := 0; s < 5; s++ {
        t14.Square(t14)
    }
    t13.Mul(t13, t14)
    for s := 0; s < 9; s++ {
        t13.Square(t13)
    }
    t12.Mul(t12, t13)
    for s := 0; s < 8; s++ {
        t12.Square(t12)
    }
    t11.Mul(t11, t12)
    for s := 0; s < 9; s++ {
        t11.Square(t11)
    }
    t11.Mul(t10, t11)
    for s := 0; s < 9; s++ {
        t11.Square(t11)
    }
    t11.Mul(z, t11)
    for s := 0; s < 8; s++ {
        t11.Square(t11)
    }
    t10.Mul(t10, t11)
    for s := 0; s < 9; s++ {
        t10.Square(t10)
    }
    t9.Mul(t9, t10)
    for s := 0; s < 8; s++ {
        t9.Square(t9)
    }
    t9.Mul(t2, t9)
    for s := 0; s < 8; s++ {
        t9.Square(t9)
    }
    t9.Mul(t3, t9)
    for s := 0; s < 8; s++ {
        t9.Square(t9)
    }
    t8.Mul(t8, t9)
    for s := 0; s < 7; s++ {
        t8.Square(t8)
    }
    t7.Mul(t7, t8)
    for s := 0; s < 7; s++ {
        t7.Square(t7)
    }
    t6.Mul(t6, t7)
    for s := 0; s < 8; s++ {
        t6.Square(t6)
    }
    t5.Mul(t5, t6)
    for s := 0; s < 6; s++ {
        t5.Square(t5)
    }
    t5.Mul(z, t5)
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
    for s := 0; s < 6; s++ {
        t0.Square(t0)
    }
    z.Mul(z, t0)
    return e.Set(z)
}

func (e *gfP2) expP(x *gfP2) *gfP2 {
    // The sequence of 56 multiplications and 250 squarings is derived from the
    // following addition chain generated with github.com/mmcloughlin/addchain v0.4.0.
    //
    //	_10      = 2*1
    //	_11      = 1 + _10
    //	_100     = 1 + _11
    //	_101     = 1 + _100
    //	_1000    = _11 + _101
    //	_1001    = 1 + _1000
    //	_1011    = _10 + _1001
    //	_1101    = _10 + _1011
    //	_10101   = _1000 + _1101
    //	_11001   = _100 + _10101
    //	_11101   = _100 + _11001
    //	_11111   = _10 + _11101
    //	_100011  = _100 + _11111
    //	_100101  = _10 + _100011
    //	_101001  = _100 + _100101
    //	_101011  = _10 + _101001
    //	_101101  = _10 + _101011
    //	_101111  = _10 + _101101
    //	_110011  = _100 + _101111
    //	_110101  = _10 + _110011
    //	_110111  = _10 + _110101
    //	_111011  = _100 + _110111
    //	_111101  = _10 + _111011
    //	_111111  = _10 + _111101
    //	_1011010 = _11101 + _111101
    //	i71      = ((_1011010 << 3 + _1001) << 33 + _10101) << 8
    //	i88      = ((_11101 + i71) << 8 + _110111) << 6 + _100011
    //	i115     = ((i88 << 6 + _101011) << 12 + _11101) << 7
    //	i128     = ((_101101 + i115) << 8 + _111111) << 2 + _11
    //	i152     = ((i128 << 5 + _1011) << 9 + _111011) << 8
    //	i173     = ((_11101 + i152) << 9 + _101001) << 9 + _11111
    //	i195     = ((i173 << 8 + _101001) << 6 + _1101) << 6
    //	i213     = ((_1011 + i195) << 7 + _1101) << 8 + _111101
    //	i234     = ((i213 << 7 + _111011) << 6 + _101101) << 6
    //	i250     = ((_101111 + i234) << 6 + _100101) << 7 + _110111
    //	i272     = ((i250 << 6 + _110011) << 6 + _11001) << 8
    //	i290     = ((_111111 + i272) << 9 + _110101) << 6 + _101
    //	return     (i290 << 9 + _101011) << 5 + _11101
    //
    var z = new(gfP2).Set(e)
    var t0 = new(gfP2)
    var t1 = new(gfP2)
    var t2 = new(gfP2)
    var t3 = new(gfP2)
    var t4 = new(gfP2)
    var t5 = new(gfP2)
    var t6 = new(gfP2)
    var t7 = new(gfP2)
    var t8 = new(gfP2)
    var t9 = new(gfP2)
    var t10 = new(gfP2)
    var t11 = new(gfP2)
    var t12 = new(gfP2)
    var t13 = new(gfP2)
    var t14 = new(gfP2)
    var t15 = new(gfP2)
    var t16 = new(gfP2)
    var t17 = new(gfP2)
    var t18 = new(gfP2)
    var t19 = new(gfP2)
    var t20 = new(gfP2)

    t3.Square(x)
    t16.Mul(x, t3)
    t10.Mul(x, t16)
    t1.Mul(x, t10)
    z.Mul(t16, t1)
    t19.Mul(x, z)
    t13.Mul(t3, t19)
    t12.Mul(t3, t13)
    t18.Mul(z, t12)
    t4.Mul(t10, t18)
    z.Mul(t10, t4)
    t15.Mul(t3, z)
    t17.Mul(t10, t15)
    t7.Mul(t3, t17)
    t14.Mul(t10, t7)
    t0.Mul(t3, t14)
    t9.Mul(t3, t0)
    t8.Mul(t3, t9)
    t5.Mul(t10, t8)
    t2.Mul(t3, t5)
    t6.Mul(t3, t2)
    t10.Mul(t10, t6)
    t11.Mul(t3, t10)
    t3.Mul(t3, t11)
    t20.Mul(z, t11)
    for s := 0; s < 3; s++ {
        t20.Square(t20)
    }
    t19.Mul(t19, t20)
    for s := 0; s < 33; s++ {
        t19.Square(t19)
    }
    t18.Mul(t18, t19)
    for s := 0; s < 8; s++ {
        t18.Square(t18)
    }
    t18.Mul(z, t18)
    for s := 0; s < 8; s++ {
        t18.Square(t18)
    }
    t18.Mul(t6, t18)
    for s := 0; s < 6; s++ {
        t18.Square(t18)
    }
    t17.Mul(t17, t18)
    for s := 0; s < 6; s++ {
        t17.Square(t17)
    }
    t17.Mul(t0, t17)
    for s := 0; s < 12; s++ {
        t17.Square(t17)
    }
    t17.Mul(z, t17)
    for s := 0; s < 7; s++ {
        t17.Square(t17)
    }
    t17.Mul(t9, t17)
    for s := 0; s < 8; s++ {
        t17.Square(t17)
    }
    t17.Mul(t3, t17)
    for s := 0; s < 2; s++ {
        t17.Square(t17)
    }
    t16.Mul(t16, t17)
    for s := 0; s < 5; s++ {
        t16.Square(t16)
    }
    t16.Mul(t13, t16)
    for s := 0; s < 9; s++ {
        t16.Square(t16)
    }
    t16.Mul(t10, t16)
    for s := 0; s < 8; s++ {
        t16.Square(t16)
    }
    t16.Mul(z, t16)
    for s := 0; s < 9; s++ {
        t16.Square(t16)
    }
    t16.Mul(t14, t16)
    for s := 0; s < 9; s++ {
        t16.Square(t16)
    }
    t15.Mul(t15, t16)
    for s := 0; s < 8; s++ {
        t15.Square(t15)
    }
    t14.Mul(t14, t15)
    for s := 0; s < 6; s++ {
        t14.Square(t14)
    }
    t14.Mul(t12, t14)
    for s := 0; s < 6; s++ {
        t14.Square(t14)
    }
    t13.Mul(t13, t14)
    for s := 0; s < 7; s++ {
        t13.Square(t13)
    }
    t12.Mul(t12, t13)
    for s := 0; s < 8; s++ {
        t12.Square(t12)
    }
    t11.Mul(t11, t12)
    for s := 0; s < 7; s++ {
        t11.Square(t11)
    }
    t10.Mul(t10, t11)
    for s := 0; s < 6; s++ {
        t10.Square(t10)
    }
    t9.Mul(t9, t10)
    for s := 0; s < 6; s++ {
        t9.Square(t9)
    }
    t8.Mul(t8, t9)
    for s := 0; s < 6; s++ {
        t8.Square(t8)
    }
    t7.Mul(t7, t8)
    for s := 0; s < 7; s++ {
        t7.Square(t7)
    }
    t6.Mul(t6, t7)
    for s := 0; s < 6; s++ {
        t6.Square(t6)
    }
    t5.Mul(t5, t6)
    for s := 0; s < 6; s++ {
        t5.Square(t5)
    }
    t4.Mul(t4, t5)
    for s := 0; s < 8; s++ {
        t4.Square(t4)
    }
    t3.Mul(t3, t4)
    for s := 0; s < 9; s++ {
        t3.Square(t3)
    }
    t2.Mul(t2, t3)
    for s := 0; s < 6; s++ {
        t2.Square(t2)
    }
    t1.Mul(t1, t2)
    for s := 0; s < 9; s++ {
        t1.Square(t1)
    }
    t0.Mul(t0, t1)
    for s := 0; s < 5; s++ {
        t0.Square(t0)
    }
    z.Mul(z, t0)
    return e.Set(z)
}

func (e *gfP2) expPMinus1Over2(x *gfP2) *gfP2 {
    // The sequence of 53 multiplications and 250 squarings is derived from the
    // following addition chain generated with github.com/mmcloughlin/addchain v0.4.0.
    //
    //	_10      = 2*1
    //	_100     = 2*_10
    //	_110     = _10 + _100
    //	_1010    = _100 + _110
    //	_1011    = 1 + _1010
    //	_1101    = _10 + _1011
    //	_10000   = _110 + _1010
    //	_10101   = _1010 + _1011
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
    //	i71      = ((_1011011 << 3 + 1) << 33 + _10101) << 8
    //	i93      = ((_11101 + i71) << 9 + _1101111) << 10 + _1110101
    //	i115     = ((2*i93 + 1) << 14 + _1110101) << 5
    //	i128     = 2*((_1101 + i115) << 9 + _1110101) + _10101
    //	i152     = ((i128 << 5 + _1011) << 9 + _111011) << 8
    //	i173     = ((_11101 + i152) << 9 + _101001) << 9 + _11111
    //	i200     = ((i173 << 8 + _101001) << 9 + _1101001) << 8
    //	i219     = ((_1100011 + i200) << 8 + _1001111) << 8 + _1011101
    //	i243     = ((i219 << 7 + _1101101) << 7 + _1011111) << 8
    //	i259     = ((_101011 + i243) << 6 + _11111) << 7 + _11011
    //	i285     = ((i259 << 9 + _1001111) << 7 + _1100011) << 8
    //	i302     = ((_1010001 + i285) << 8 + _1000101) << 6 + _11111
    //	return     2*i302
    //
    var z = new(gfP2).Set(e)
    var t0 = new(gfP2)
    var t1 = new(gfP2)
    var t2 = new(gfP2)
    var t3 = new(gfP2)
    var t4 = new(gfP2)
    var t5 = new(gfP2)
    var t6 = new(gfP2)
    var t7 = new(gfP2)
    var t8 = new(gfP2)
    var t9 = new(gfP2)
    var t10 = new(gfP2)
    var t11 = new(gfP2)
    var t12 = new(gfP2)
    var t13 = new(gfP2)
    var t14 = new(gfP2)
    var t15 = new(gfP2)
    var t16 = new(gfP2)
    var t17 = new(gfP2)
    var t18 = new(gfP2)

    t17.Square(x)
    t7.Square(t17)
    t15.Mul(t17, t7)
    t2.Mul(t7, t15)
    t13.Mul(x, t2)
    t16.Mul(t17, t13)
    t0.Mul(t15, t2)
    t14.Mul(t2, t13)
    t4.Mul(t15, t14)
    t11.Mul(t17, t4)
    z.Mul(t17, t11)
    t10.Mul(t2, z)
    t5.Mul(t17, t10)
    t12.Mul(t0, t5)
    t0.Mul(t2, t12)
    t3.Mul(t2, t0)
    t1.Mul(t17, t3)
    t18.Mul(t2, t1)
    t8.Mul(t17, t18)
    t6.Mul(t17, t8)
    t2.Mul(t7, t6)
    t9.Mul(t15, t2)
    t7.Mul(t7, t9)
    t17.Mul(t17, t7)
    t15.Mul(t15, t17)
    for s := 0; s < 3; s++ {
        t18.Square(t18)
    }
    t18.Mul(x, t18)
    for s := 0; s < 33; s++ {
        t18.Square(t18)
    }
    t18.Mul(t14, t18)
    for s := 0; s < 8; s++ {
        t18.Square(t18)
    }
    t18.Mul(t11, t18)
    for s := 0; s < 9; s++ {
        t18.Square(t18)
    }
    t17.Mul(t17, t18)
    for s := 0; s < 10; s++ {
        t17.Square(t17)
    }
    t17.Mul(t15, t17)
    t17.Square(t17)
    t17.Mul(x, t17)
    for s := 0; s < 14; s++ {
        t17.Square(t17)
    }
    t17.Mul(t15, t17)
    for s := 0; s < 5; s++ {
        t17.Square(t17)
    }
    t16.Mul(t16, t17)
    for s := 0; s < 9; s++ {
        t16.Square(t16)
    }
    t15.Mul(t15, t16)
    t15.Square(t15)
    t14.Mul(t14, t15)
    for s := 0; s < 5; s++ {
        t14.Square(t14)
    }
    t13.Mul(t13, t14)
    for s := 0; s < 9; s++ {
        t13.Square(t13)
    }
    t12.Mul(t12, t13)
    for s := 0; s < 8; s++ {
        t12.Square(t12)
    }
    t11.Mul(t11, t12)
    for s := 0; s < 9; s++ {
        t11.Square(t11)
    }
    t11.Mul(t10, t11)
    for s := 0; s < 9; s++ {
        t11.Square(t11)
    }
    t11.Mul(z, t11)
    for s := 0; s < 8; s++ {
        t11.Square(t11)
    }
    t10.Mul(t10, t11)
    for s := 0; s < 9; s++ {
        t10.Square(t10)
    }
    t9.Mul(t9, t10)
    for s := 0; s < 8; s++ {
        t9.Square(t9)
    }
    t9.Mul(t2, t9)
    for s := 0; s < 8; s++ {
        t9.Square(t9)
    }
    t9.Mul(t3, t9)
    for s := 0; s < 8; s++ {
        t9.Square(t9)
    }
    t8.Mul(t8, t9)
    for s := 0; s < 7; s++ {
        t8.Square(t8)
    }
    t7.Mul(t7, t8)
    for s := 0; s < 7; s++ {
        t7.Square(t7)
    }
    t6.Mul(t6, t7)
    for s := 0; s < 8; s++ {
        t6.Square(t6)
    }
    t5.Mul(t5, t6)
    for s := 0; s < 6; s++ {
        t5.Square(t5)
    }
    t5.Mul(z, t5)
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
    for s := 0; s < 6; s++ {
        t0.Square(t0)
    }
    z.Mul(z, t0)
    z.Square(z)
    return e.Set(z)
}
