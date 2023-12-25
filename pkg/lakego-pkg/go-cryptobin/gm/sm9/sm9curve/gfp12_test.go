package sm9curve

import (
    "math/big"
    "testing"
)

var p6 = gfP6{
    gfP2{
        *fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
        *fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
    },
    gfP2{
        *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
        *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
    },
    gfP2{
        *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
        *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
    },
}

func testGfP12Square(t *testing.T, x *gfP12) {
    xmulx := &gfP12{}
    xmulx.Mul(x, x)
    xmulx = gfP12Decode(xmulx)

    x2 := &gfP12{}
    x2.Square(x)
    x2 = gfP12Decode(x2)

    if *xmulx != *x2 {
        t.Errorf("xmulx=%v, x2=%v", xmulx, x2)
    }
}

func Test_gfP12Square(t *testing.T) {
    x := &gfP12{
        p6,
        p6,
    }
    testGfP12Square(t, x)

    x = &gfP12{
        p6,
        *(&gfP6{}).SetOne(),
    }
    testGfP12Square(t, x)

    x = &gfP12{
        *(&gfP6{}).SetOne(),
        p6,
    }
    testGfP12Square(t, x)

    x = &gfP12{
        *(&gfP6{}).SetZero(),
        p6,
    }
    testGfP12Square(t, x)

    x = &gfP12{
        p6,
        *(&gfP6{}).SetZero(),
    }
    testGfP12Square(t, x)
}

func testGfP12Invert(t *testing.T, x *gfP12) {
    xInv := &gfP12{}
    xInv.Invert(x)

    y := &gfP12{}
    y.Mul(x, xInv)
    if !y.IsOne() {
        t.Fail()
    }
}

func Test_gfP12Invert(t *testing.T) {
    x := &gfP12{
        *(&gfP6{}).SetZero(),
        p6,
    }
    testGfP12Invert(t, x)
    x = &gfP12{
        *(&gfP6{}).SetOne(),
        p6,
    }
    testGfP12Invert(t, x)
}

func TestSToPMinus1Over2(t *testing.T) {
    expected := &gfP2{}
    expected.y.Set(fromBigInt(bigFromHex("3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b")))
    expected.x.Set(zero)

    s := &gfP6{}
    s.SetS()
    s.Exp(s, pMinus1Over2Big)
    if !(s.x.IsZero() && s.y.IsZero() && s.z == *expected) {
        s = gfP6Decode(s)
        t.Errorf("not same as expected %v\n", s)
    }
}

func Test_gfP12Frobenius(t *testing.T) {
    x := &gfP12{
        p6,
        p6,
    }
    expected := &gfP12{}
    expected.Exp(x, p)
    got := &gfP12{}
    got.Frobenius(x)
    if *expected != *got {
        t.Errorf("got %v, expected %v", got, expected)
    }
}

func TestSToPSquaredMinus1Over2(t *testing.T) {
    s := &gfP6{}
    s.SetS()
    p2 := new(big.Int).Mul(p, p)
    p2 = new(big.Int).Sub(p2, big.NewInt(1))
    p2.Rsh(p2, 1)
    s.Exp(s, p2)

    expected := &gfP2{}
    expected.y.Set(fromBigInt(bigFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334")))
    expected.x.Set(zero)

    if !(s.x.IsZero() && s.y.IsZero() && s.z == *expected) {
        s = gfP6Decode(s)
        t.Errorf("not same as expected %v\n", s)
    }
}

func Test_gfP12FrobeniusP2(t *testing.T) {
    x := &gfP12{
        p6,
        p6,
    }
    expected := &gfP12{}
    p2 := new(big.Int).Mul(p, p)
    expected.Exp(x, p2)
    got := &gfP12{}
    got.FrobeniusP2(x)
    if *expected != *got {
        t.Errorf("got %v, expected %v", got, expected)
    }
}

func TestSToP4Minus1Over2(t *testing.T) {
    s := &gfP6{}
    s.SetS()
    p4 := new(big.Int).Mul(p, p)
    p4.Mul(p4, p4)
    p4 = new(big.Int).Sub(p4, big.NewInt(1))
    p4.Rsh(p4, 1)
    s.Exp(s, p4)

    expected := &gfP2{}
    expected.y.Set(fromBigInt(bigFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65333")))
    expected.x.Set(zero)

    if !(s.x.IsZero() && s.y.IsZero() && s.z == *expected) {
        s = gfP6Decode(s)
        t.Errorf("not same as expected %v\n", s)
    }
}

func Test_gfP12FrobeniusP4(t *testing.T) {
    x := &gfP12{
        p6,
        p6,
    }
    expected := &gfP12{}
    p4 := new(big.Int).Mul(p, p)
    p4.Mul(p4, p4)
    expected.Exp(x, p4)
    got := &gfP12{}
    got.FrobeniusP4(x)
    if *expected != *got {
        t.Errorf("got %v, expected %v", got, expected)
    }
}

func Test_gfP12b6FrobeniusP6(t *testing.T) {
    x := &gfP12{
        p6,
        p6,
    }
    expected := &gfP12{}
    p6 := new(big.Int).Mul(p, p)
    p6.Mul(p6, p)
    p6.Mul(p6, p6)
    expected.Exp(x, p6)
    got := &gfP12{}
    got.FrobeniusP6(x)
    if *expected != *got {
        t.Errorf("got %v, expected %v", got, expected)
    }
}

func BenchmarkGfP12Frobenius(b *testing.B) {
    x := &gfP12{
        p6,
        p6,
    }
    expected := &gfP12{}
    expected.Exp(x, p)
    got := &gfP12{}
    b.ReportAllocs()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        got.Frobenius(x)
        if *expected != *got {
            b.Errorf("got %v, expected %v", got, expected)
        }
    }
}
