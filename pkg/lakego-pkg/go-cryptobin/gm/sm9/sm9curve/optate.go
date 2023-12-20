package sm9curve

func lineFunctionAdd(r, P *twistPoint, Q *curvePoint, R2 *gfP2) (a, b, c *gfP2, rOut *twistPoint) {
    // See the mixed addition algorithm from "Faster Computation of the
    // Tate Pairing", http://arxiv.org/pdf/0904.0854v3.pdf
    B := (&gfP2{}).Mul(&P.x, &r.t)

    D := (&gfP2{}).Add(&P.y, &r.z)
    D.Square(D).Sub(D, R2).Sub(D, &r.t).Mul(D, &r.t)

    H := (&gfP2{}).Sub(B, &r.x)
    I := (&gfP2{}).Square(H)

    E := (&gfP2{}).Add(I, I)
    E.Add(E, E)

    J := (&gfP2{}).Mul(H, E)

    L1 := (&gfP2{}).Sub(D, &r.y)
    L1.Sub(L1, &r.y)

    V := (&gfP2{}).Mul(&r.x, E)

    rOut = &twistPoint{}
    rOut.x.Square(L1).Sub(&rOut.x, J).Sub(&rOut.x, V).Sub(&rOut.x, V)

    rOut.z.Add(&r.z, H).Square(&rOut.z).Sub(&rOut.z, &r.t).Sub(&rOut.z, I)

    t := (&gfP2{}).Sub(V, &rOut.x)
    t.Mul(t, L1)
    t2 := (&gfP2{}).Mul(&r.y, J)
    t2.Add(t2, t2)
    rOut.y.Sub(t, t2)

    rOut.t.Square(&rOut.z)

    t.Add(&P.y, &rOut.z).Square(t).Sub(t, R2).Sub(t, &rOut.t)

    t2.Mul(L1, &P.x)
    t2.Add(t2, t2)
    a = (&gfP2{}).Sub(t2, t)

    c = (&gfP2{}).MulScalar(&rOut.z, &Q.y)
    c.Add(c, c)

    b = (&gfP2{}).Neg(L1)
    b.MulScalar(b, &Q.x).Add(b, b)

    return
}

func lineFunctionDouble(r *twistPoint, Q *curvePoint) (a, b, c *gfP2, rOut *twistPoint) {
    // See the doubling algorithm for a=0 from "Faster Computation of the
    // Tate Pairing", http://arxiv.org/pdf/0904.0854v3.pdf
    A := (&gfP2{}).Square(&r.x)
    B := (&gfP2{}).Square(&r.y)
    C := (&gfP2{}).Square(B)

    D := (&gfP2{}).Add(&r.x, B)
    D.Square(D).Sub(D, A).Sub(D, C).Add(D, D)

    E := (&gfP2{}).Add(A, A)
    E.Add(E, A)

    G := (&gfP2{}).Square(E)

    rOut = &twistPoint{}
    rOut.x.Sub(G, D).Sub(&rOut.x, D)

    rOut.z.Add(&r.y, &r.z).Square(&rOut.z).Sub(&rOut.z, B).Sub(&rOut.z, &r.t)

    rOut.y.Sub(D, &rOut.x).Mul(&rOut.y, E)
    t := (&gfP2{}).Add(C, C)
    t.Add(t, t).Add(t, t)
    rOut.y.Sub(&rOut.y, t)

    rOut.t.Square(&rOut.z)

    t.Mul(E, &r.t).Add(t, t)
    b = (&gfP2{}).Neg(t)
    b.MulScalar(b, &Q.x)

    a = (&gfP2{}).Add(&r.x, E)
    a.Square(a).Sub(a, A).Sub(a, G)
    t.Add(B, B).Add(t, t)
    a.Sub(a, t)

    c = (&gfP2{}).Mul(&rOut.z, &r.t)
    c.Add(c, c).MulScalar(c, &Q.y)

    return
}

func mulLine(ret *gfP12, a, b, c *gfP2) {
    a2 := &gfP6{}
    a2.y.Set(a)
    a2.z.Set(b)
    a2.Mul(a2, &ret.x)
    t3 := (&gfP6{}).MulScalar(&ret.y, c)

    t := (&gfP2{}).Add(b, c)
    t2 := &gfP6{}
    t2.y.Set(a)
    t2.z.Set(t)
    ret.x.Add(&ret.x, &ret.y)

    ret.y.Set(t3)

    ret.x.Mul(&ret.x, t2).Sub(&ret.x, a2).Sub(&ret.x, &ret.y)
    a2.MulTau(a2)
    ret.y.Add(&ret.y, a2)
}

func mulLine2(ret *gfP12, a, b, c *gfP2) {
    a2 := &gfP12{}
    zero := &gfP2{}
    zero.SetZero()

    a2.x.x = *zero
    a2.x.y = *a
    a2.x.z = *b
    a2.y.x = *zero
    a2.y.y = *zero
    a2.y.z = *c

    ret.Mul(ret, a2)
}

// sixuPlus2NAF is 6u+2 in non-adjacent form.
var sixuPlus2NAF = []int8{0, -1, 0, 0, 0, 0, 1, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, -1, 0, -1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1}

// miller implements the Miller loop for calculating the Optimal Ate pairing.
// See algorithm 1 from http://cryptojedi.org/papers/dclxvi-20100714.pdf
func miller(Q *twistPoint, P *curvePoint) *gfP12 {
    ret := (&gfP12{}).SetOne()

    aAffine := &twistPoint{}
    aAffine.Set(Q)
    aAffine.MakeAffine()

    bAffine := &curvePoint{}
    bAffine.Set(P)
    bAffine.MakeAffine()

    minusA := &twistPoint{}
    minusA.Neg(aAffine)

    r := &twistPoint{}
    r.Set(aAffine)

    R2 := (&gfP2{}).Square(&aAffine.y)

    for i := len(sixuPlus2NAF) - 1; i > 0; i-- {
        a, b, c, newR := lineFunctionDouble(r, bAffine)
        if i != len(sixuPlus2NAF)-1 {
            ret.Square(ret)
        }

        mulLine(ret, a, b, c)
        r = newR

        switch sixuPlus2NAF[i-1] {
        case 1:
            a, b, c, newR = lineFunctionAdd(r, aAffine, bAffine, R2)
        case -1:
            a, b, c, newR = lineFunctionAdd(r, minusA, bAffine, R2)
        default:
            continue
        }

        mulLine(ret, a, b, c)
        r = newR

    }

    // In order to calculate Q1 we have to convert q from the sextic twist
    // to the full GF(p^12) group, apply the Frobenius there, and convert
    // back.
    //
    // The twist isomorphism is (x', y') -> (xω², yω³). If we consider just
    // x for a moment, then after applying the Frobenius, we have x̄ω^(2p)
    // where x̄ is the conjugate of x. If we are going to apply the inverse
    // isomorphism we need a value with a single coefficient of ω² so we
    // rewrite this as x̄ω^(2p-2)ω². ξ⁶ = ω and, due to the construction of
    // p, 2p-2 is a multiple of six. Therefore we can rewrite as
    // x̄ξ^((p-1)/3)ω² and applying the inverse isomorphism eliminates the
    // ω².
    //
    // A similar argument can be made for the y value.

    q1 := &twistPoint{}
    q1.x.Conjugate(&aAffine.x).MulScalar(&q1.x, xiToPMinus1Over3)
    q1.y.Conjugate(&aAffine.y).MulScalar(&q1.y, xiToPMinus1Over2)
    q1.z.SetOne()
    q1.t.SetOne()

    // For Q2 we are applying the p² Frobenius. The two conjugations cancel
    // out and we are left only with the factors from the isomorphism. In
    // the case of x, we end up with a pure number which is why
    // xiToPSquaredMinus1Over3 is ∈ GF(p). With y we get a factor of -1. We
    // ignore this to end up with -Q2.

    minusQ2 := &twistPoint{}
    minusQ2.x.MulScalar(&aAffine.x, xiToPSquaredMinus1Over3)
    minusQ2.y.Set(&aAffine.y)
    minusQ2.z.SetOne()
    minusQ2.t.SetOne()

    R2.Square(&q1.y)
    a, b, c, newR := lineFunctionAdd(r, q1, bAffine, R2)
    mulLine(ret, a, b, c)
    r = newR

    R2.Square(&minusQ2.y)
    a, b, c, newR = lineFunctionAdd(r, minusQ2, bAffine, R2)
    mulLine(ret, a, b, c)
    r = newR

    return ret
}

// finalExponentiation computes the (p¹²-1)/Order-th power of an element of
// GF(p¹²) to obtain an element of GT (steps 13-15 of algorithm 1 from
// http://cryptojedi.org/papers/dclxvi-20100714.pdf)
func finalExponentiation(in *gfP12) *gfP12 {
    t1 := &gfP12{}

    // This is the p^6-Frobenius
    t1.x.Neg(&in.x)
    t1.y.Set(&in.y)

    inv := &gfP12{}
    inv.Invert(in)
    t1.Mul(t1, inv)

    //p^2+1
    t2 := (&gfP12{}).FrobeniusP2(t1)
    t1.Mul(t1, t2)

    fp := (&gfP12{}).Frobenius(t1)
    fp2 := (&gfP12{}).FrobeniusP2(t1)
    fp3 := (&gfP12{}).Frobenius(fp2)

    fu := (&gfP12{}).Exp(t1, u)
    fu2 := (&gfP12{}).Exp(fu, u)
    fu3 := (&gfP12{}).Exp(fu2, u)

    y3 := (&gfP12{}).Frobenius(fu)
    fu2p := (&gfP12{}).Frobenius(fu2)
    fu3p := (&gfP12{}).Frobenius(fu3)
    y2 := (&gfP12{}).FrobeniusP2(fu2)

    y0 := &gfP12{}
    y0.Mul(fp, fp2).Mul(y0, fp3)

    y1 := (&gfP12{}).Conjugate(t1)
    y5 := (&gfP12{}).Conjugate(fu2)
    y3.Conjugate(y3)
    y4 := (&gfP12{}).Mul(fu, fu2p)
    y4.Conjugate(y4)

    y6 := (&gfP12{}).Mul(fu3, fu3p)
    y6.Conjugate(y6)

    t0 := (&gfP12{}).Square(y6)
    t0.Mul(t0, y4).Mul(t0, y5)
    t1.Mul(y3, y5).Mul(t1, t0)
    t0.Mul(t0, y2)
    t1.Square(t1).Mul(t1, t0).Square(t1)
    t0.Mul(t1, y1)
    t1.Mul(t1, y0)
    t0.Square(t0).Mul(t0, t1)

    return t0
}

////steps 13-15 of algorithm 1 from
////"Implementing cryptographic pairings over BN curves".
//NOT CORRECT!!
//func finalExponentiation2(in *gfP12) *gfP12 {
//	t1 := &gfP12{}
//
//	// This is the p^6-Frobenius
//	t1.x.Neg(&in.x)
//	t1.y.Set(&in.y)
//
//	inv := &gfP12{}
//	inv.Invert(in)
//	t1.Mul(t1, inv)
//
//	//p^2+1
//	t2 := (&gfP12{}).FrobeniusP2(t1)
//	t1.Mul(t1, t2)
//
//	//(p^4-p^2+1)/n
//	six := big.NewInt(6)
//	five := big.NewInt(5)
//	one := big.NewInt(1)
//	nine := big.NewInt(9)
//	four := big.NewInt(4)
//
//	sixxMinusFive := new(big.Int).Mul(six,u)
//	sixxMinusFive.Sub(sixxMinusFive,five)
//
//	a := (&gfP12{}).Exp(t1,sixxMinusFive)
//	b := (&gfP12{}).Frobenius(a)
//	b.Mul(b,a)
//
//	fp := (&gfP12{}).Frobenius(t1)
//	fpsqr := (&gfP12{}).Square(fp)
//	fp2 := (&gfP12{}).FrobeniusP2(t1)
//	fp3 := (&gfP12{}).Frobenius(fp2)
//
//	t0 := (&gfP12{}).Mul(b,fpsqr)
//	t0.Mul(t0,fp2)
//
//	sixxSquarePlusOne := new(big.Int).Mul(u,u)
//	sixxSquarePlusOne.Mul(six,sixxSquarePlusOne)
//	sixxSquarePlusOne.Add(sixxSquarePlusOne,one)
//
//	t0.Exp(t0,sixxSquarePlusOne)
//
//	t0.Mul(t0,fp3).Mul(t0,b).Mul(t0,a)
//
//	tmp1 := (&gfP12{}).Mul(t1,fp)
//	tmp1.Exp(tmp1,nine)
//	temp2 := (&gfP12{}).Exp(t1,four)
//	t0.Mul(t0,tmp1).Mul(t0,temp2)
//
//	return t0
//}

func optimalAte(a *twistPoint, b *curvePoint) *gfP12 {
    e := miller(a, b)
    ret := finalExponentiation(e)

    if a.IsInfinity() || b.IsInfinity() {
        ret.SetOne()
    }
    return ret
}
