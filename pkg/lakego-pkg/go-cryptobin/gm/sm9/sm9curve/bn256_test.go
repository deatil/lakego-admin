package sm9curve

import (
    "fmt"
    "testing"

    "bytes"
    "crypto/rand"
)

func TestG1(t *testing.T) {
    k, Ga, err := RandomG1(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    ma := Ga.Marshal()

    Gb := new(G1).ScalarBaseMult(k)

    mb := Gb.Marshal()

    if !bytes.Equal(ma, mb) {
        t.Fatal("bytes are different")
    }
}

func TestG1Marshal(t *testing.T) {
    _, Ga, err := RandomG1(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    ma := Ga.Marshal()

    Gb := new(G1)
    _, err = Gb.Unmarshal(ma)
    if err != nil {
        t.Fatal(err)
    }
    mb := Gb.Marshal()

    if !bytes.Equal(ma, mb) {
        t.Fatal("bytes are different")
    }
}

func TestG2(t *testing.T) {
    k, Ga, err := RandomG2(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    ma := Ga.Marshal()

    Gb := new(G2).ScalarBaseMult(k)
    mb := Gb.Marshal()

    if !bytes.Equal(ma, mb) {
        t.Fatal("bytes are different")
    }
}

func TestG2Marshal(t *testing.T) {
    _, Ga, err := RandomG2(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    ma := Ga.Marshal()

    Gb := new(G2)
    _, err = Gb.Unmarshal(ma)
    if err != nil {
        t.Fatal(err)
    }
    mb := Gb.Marshal()

    if !bytes.Equal(ma, mb) {
        t.Fatal("bytes are different")
    }
}

func TestGT(t *testing.T) {
    k, Ga, err := RandomGT(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    ma := Ga.Marshal()

    Gb := &GT{gfP12Gen}
    Gb.ScalarMult(Gb, k)
    mb := Gb.Marshal()

    if !bytes.Equal(ma, mb) {
        t.Fatal("bytes are different")
    }
}

func TestGTMarshal(t *testing.T) {
    _, Ga, err := RandomGT(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    ma := Ga.Marshal()

    Gb := new(GT)
    _, err = Gb.Unmarshal(ma)
    if err != nil {
        t.Fatal(err)
    }
    mb := Gb.Marshal()

    if !bytes.Equal(ma, mb) {
        t.Fatal("bytes are different")
    }
}

func TestBilinearity(t *testing.T) {
    for i := 0; i < 2; i++ {
        a, p1, _ := RandomG1(rand.Reader)
        b, p2, _ := RandomG2(rand.Reader)
        e1 := Pair(p1, p2)

        e2 := Pair(&G1{curveGen}, &G2{twistGen})
        e2.ScalarMult(e2, a)
        e2.ScalarMult(e2, b)

        if *e1.p != *e2.p {
            t.Fatalf("bad pairing result: %s", e1)
        }
    }
}

func TestTripartiteDiffieHellman(t *testing.T) {
    a, _ := rand.Int(rand.Reader, Order)
    b, _ := rand.Int(rand.Reader, Order)
    c, _ := rand.Int(rand.Reader, Order)

    pa, pb, pc := new(G1), new(G1), new(G1)
    qa, qb, qc := new(G2), new(G2), new(G2)

    pa.Unmarshal(new(G1).ScalarBaseMult(a).Marshal())
    qa.Unmarshal(new(G2).ScalarBaseMult(a).Marshal())
    pb.Unmarshal(new(G1).ScalarBaseMult(b).Marshal())
    qb.Unmarshal(new(G2).ScalarBaseMult(b).Marshal())
    pc.Unmarshal(new(G1).ScalarBaseMult(c).Marshal())
    qc.Unmarshal(new(G2).ScalarBaseMult(c).Marshal())

    k1 := Pair(pb, qc)
    k1.ScalarMult(k1, a)
    k1Bytes := k1.Marshal()

    k2 := Pair(pc, qa)
    k2.ScalarMult(k2, b)
    k2Bytes := k2.Marshal()

    k3 := Pair(pa, qb)
    k3.ScalarMult(k3, c)
    k3Bytes := k3.Marshal()

    if !bytes.Equal(k1Bytes, k2Bytes) || !bytes.Equal(k2Bytes, k3Bytes) {
        t.Errorf("keys didn't agree")
    }
}

func TestSelfAddG1(t *testing.T) {
    _, Ga, err := RandomG1(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    Gb := &G1{curveGen}
    Gb.p.Double(Ga.p)
    mb := Gb.Marshal()

    Ga.Add(Ga, Ga)
    ma := Ga.Marshal()

    if !bytes.Equal(ma, mb) {
        t.Fatal("bytes are different")
    }
}

func TestSelfAddG2(t *testing.T) {
    _, Ga, err := RandomG2(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    Gb := &G2{twistGen}
    Gb.p.Double(Ga.p)
    mb := Gb.Marshal()

    Ga.Add(Ga, Ga)
    ma := Ga.Marshal()

    if !bytes.Equal(ma, mb) {
        t.Fatal("bytes are different")
    }
}

func TestDirtyUnmarshal(t *testing.T) {
    _, Ga, err := RandomG2(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    ma := Ga.Marshal()

    if _, err := Ga.Unmarshal(ma); err != nil {
        t.Fatal(err)
    }
}

//// xiToPSquaredMinus1Over3 is ξ^((p²-1)/3) where ξ = bi.
//func TestXiToPSquaredMinus1Over3(t *testing.T) {
//	one := new(big.Int).SetInt64(1)
//	three := new(big.Int).SetInt64(3)
//	p2 := new(big.Int).Mul(p, p)
//	p2.Sub(p2, one)
//	p2.Div(p2, three)
//
//	a := gfP2{bi, *newGFp(0)}
//
//	b := new(gfP2).GFp2Exp(&a, p2)
//
//	fmt.Println(b)
//	b.y.Println()
//	var c gfP
//	montDecode(&c, &b.y)
//	c.Println()
//}
//
//// xiTo2PSquaredMinus2Over3 is ξ^((2p²-2)/3) where ξ = bi (a cubic root of unity, mod p).
//func TestXiTo2PSquaredMinus2Over3(t *testing.T) {
//	one := new(big.Int).SetInt64(1)
//	two := new(big.Int).SetInt64(2)
//	three := new(big.Int).SetInt64(3)
//	p2 := new(big.Int).Mul(p, p)
//	p2.Sub(p2, one)
//	p2.Mul(p2, two)
//	p2.Div(p2, three)
//
//	a := gfP2{bi, *newGFp(0)}
//
//	b := new(gfP2).GFp2Exp(&a, p2)
//
//	fmt.Println(b)
//	b.y.Println()
//
//	var c gfP
//	montDecode(&c, &b.y)
//	c.Println()
//
//
//}
//
//// xiToPSquaredMinus1Over6 is ξ^((1p²-1)/6) where ξ = bi (a cubic root of -1, mod p).
//func TestXiToPSquaredMinus1Over6(t *testing.T) {
//	one := new(big.Int).SetInt64(1)
//	six := new(big.Int).SetInt64(6)
//	p2 := new(big.Int).Mul(p, p)
//	p2.Sub(p2, one)
//	p2.Div(p2, six)
//
//	a := gfP2{bi, *newGFp(0)}
//
//	b := new(gfP2).GFp2Exp(&a, p2)
//
//	fmt.Println(b)
//	b.y.Println()
//	var c gfP
//	montDecode(&c, &b.y)
//	c.Println()
//}
//
//// xiToPMinus1Over2 is ξ^((p-1)/2) where ξ = bi.
//func TestXiToPMinus1Over2(t *testing.T) {
//	one := new(big.Int).SetInt64(1)
//	two := new(big.Int).SetInt64(2)
//	psubone := new(big.Int).Sub(p, one)
//	psubone.Div(psubone, two)
//
//	a := gfP2{bi, *newGFp(0)}
//
//	b := new(gfP2).GFp2Exp(&a, psubone)
//
//	fmt.Println(b)
//	b.y.Println()
//	var c gfP
//	montDecode(&c, &b.y)
//	c.Println()
//}
//
//// xiToPMinus1Over3 is ξ^((p-1)/3) where ξ = bi.
//func TestXiToPMinus1Over3(t *testing.T) {
//	one := new(big.Int).SetInt64(1)
//	three := new(big.Int).SetInt64(3)
//	psubone := new(big.Int).Sub(p, one)
//	psubone.Div(psubone, three)
//
//	a := gfP2{bi, *newGFp(0)}
//
//	b := new(gfP2).GFp2Exp(&a, psubone)
//	fmt.Println(b)
//	b.y.Println()
//	var c gfP
//	montDecode(&c, &b.y)
//	c.Println()
//}
//
//// xiTo2PMinus2Over3 is ξ^((2p-2)/3) where ξ = bi.
//func TestXiTo2PMinus2Over3(t *testing.T) {
//	one := new(big.Int).SetInt64(1)
//	two := new(big.Int).SetInt64(2)
//	three := new(big.Int).SetInt64(3)
//	psubone := new(big.Int).Sub(p, one)
//	psubone.Mul(psubone, two)
//	psubone.Div(psubone, three)
//
//	a := gfP2{bi, *newGFp(0)}
//
//	b := new(gfP2).GFp2Exp(&a, psubone)
//
//	fmt.Println(b)
//	b.y.Println()
//	var c gfP
//	montDecode(&c, &b.y)
//	c.Println()
//}
//
//// xiToPMinus1Over6 is ξ^((p-1)/6) where ξ = bi.
//func TestXiToPMinus1Over6(t *testing.T) {
//	one := new(big.Int).SetInt64(1)
//	six := new(big.Int).SetInt64(6)
//	psubone := new(big.Int).Sub(p, one)
//	psubone.Div(psubone, six)
//
//	a := gfP2{bi, *newGFp(0)}
//
//	b := new(gfP2).GFp2Exp(&a, psubone)
//
//	fmt.Println(b)
//	b.y.Println()
//	var c gfP
//	montDecode(&c, &b.y)
//	c.Println()
//}

//func TestGens(t *testing.T) {
//	// s is the Montgomery encoding of the square root of -3. Then, s = sqrt(-3) * 2^256 mod p.
//	negThree := newGFp(-3)
//	s := new(gfP)
//	s.Sqrt(negThree)
//	fmt.Println(s.String())
//	// sMinus1Over2 is the Montgomery encoding of (s-1)/2. Then, sMinus1Over2 = ( (s-1) / 2) * 2^256 mod p.
//	sMinus1Over2 := new(gfP)
//	sMinus1Over2.Set(s)
//	one := newGFp(1)
//	gfpSub(sMinus1Over2, s, one)
//	two := newGFp(2)
//	inverse := new(gfP)
//	inverse.Invert(two)
//	gfpMul(sMinus1Over2, sMinus1Over2, inverse)
//	fmt.Println(sMinus1Over2.String())
//}

func BenchmarkG1(b *testing.B) {
    x, _ := rand.Int(rand.Reader, Order)
    b.ResetTimer()

    for i := 0; i < b.N; i++ {
        new(G1).ScalarBaseMult(x)
    }
}

func BenchmarkG2(b *testing.B) {
    x, _ := rand.Int(rand.Reader, Order)
    b.ResetTimer()

    for i := 0; i < b.N; i++ {
        new(G2).ScalarBaseMult(x)
    }
}

func BenchmarkGT(b *testing.B) {
    x, _ := rand.Int(rand.Reader, Order)
    b.ResetTimer()

    for i := 0; i < b.N; i++ {
        new(GT).ScalarBaseMult(x)
    }
}

func BenchmarkPairing(b *testing.B) {
    for i := 0; i < b.N; i++ {
        Pair(&G1{curveGen}, &G2{twistGen})
    }
}

func TestMiller(t *testing.T) {
    gt := Pair(&G1{curveGen}, &G2{twistGen})

    fmt.Println(gt.String())
}
