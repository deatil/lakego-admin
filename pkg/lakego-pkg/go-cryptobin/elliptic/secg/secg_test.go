package secg

import (
    "bufio"
    "testing"
    "math/big"
    "crypto/rand"
    "crypto/ecdsa"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/elliptic/base_elliptic"
)

var (
    allCurves = []struct {
        name  string
        curve base_elliptic.Curve
    }{
        {"sect113r1", Sect113r1()},
        {"sect113r2", Sect113r2()},
        {"sect131r1", Sect131r1()},
        {"sect131r2", Sect131r2()},
        {"sect163k1", Sect163k1()},
        {"sect163r1", Sect163r1()},
        {"sect163r2", Sect163r2()},
        {"sect193r1", Sect193r1()},
        {"sect193r2", Sect193r2()},
        {"sect233k1", Sect233k1()},
        {"sect233r1", Sect233r1()},
        {"sect239k1", Sect239k1()},
        {"sect283k1", Sect283k1()},
        {"sect283r1", Sect283r1()},
        {"sect409k1", Sect409k1()},
        {"sect409r1", Sect409r1()},
        {"sect571k1", Sect571k1()},
        {"sect571r1", Sect571r1()},
    }
)

type testCase struct {
    Qx, Qy *big.Int
    Fail   bool
}

func testPoint(t *testing.T, testCases []testCase, curve base_elliptic.Curve) {
    for idx, tc := range testCases {
        ok := curve.IsOnCurve(tc.Qx, tc.Qy)
        if ok == tc.Fail {
            t.Errorf("%d: Verify failed, got:%v want:%v", idx, ok, !tc.Fail)
            return
        }
    }
}

var (
    rnd = bufio.NewReaderSize(rand.Reader, 1<<15)
)

type internalTestcase struct {
    x1, y1 *big.Int
    x2, y2 *big.Int
    x, y   *big.Int
}

func testAllCurves(t *testing.T, f func(*testing.T, base_elliptic.Curve)) {
    for _, test := range allCurves {
        test := test
        t.Run(test.name, func(t *testing.T) {
            f(t, test.curve)
        })
    }
}

func getK(c base_elliptic.Curve) []byte {
    k, _ := rand.Int(rnd, c.Params().N)
    return k.Bytes()
}

func TestScalarBaseMult(t *testing.T) {
    testAllCurves(t, func(t *testing.T, c base_elliptic.Curve) {
        if c.BinaryParams().Gx.BitLen() == 0 || c.BinaryParams().Gy.BitLen() == 0 {
            t.Skip()
            return
        }

        x, y := c.ScalarBaseMult(getK(c))
        if !c.IsOnCurve(x, y) {
            t.Fail()
        }
    })
}

func TestScalarMult(t *testing.T) {
    testAllCurves(t, func(t *testing.T, c base_elliptic.Curve) {
        if c.BinaryParams().Gx.BitLen() == 0 || c.BinaryParams().Gy.BitLen() == 0 {
            t.Skip()
            return
        }

        x1, y1 := c.ScalarBaseMult(getK(c))
        if !c.IsOnCurve(x1, y1) {
            t.Fail()
        }

        x, y := c.ScalarMult(x1, y1, getK(c))
        if !c.IsOnCurve(x, y) {
            t.Fail()
        }
    })
}

func TestDouble(t *testing.T) {
    testAllCurves(t, func(t *testing.T, c base_elliptic.Curve) {
        if c.BinaryParams().Gx.BitLen() == 0 || c.BinaryParams().Gy.BitLen() == 0 {
            t.Skip()
            return
        }

        x1, y1 := c.ScalarBaseMult(getK(c))
        if !c.IsOnCurve(x1, y1) {
            t.Fail()
        }

        x, y := c.Double(x1, y1)
        if !c.IsOnCurve(x, y) {
            t.Fail()
        }
    })
}

func TestAdd(t *testing.T) {
    testAllCurves(t, func(t *testing.T, c base_elliptic.Curve) {
        if c.BinaryParams().Gx.BitLen() == 0 || c.BinaryParams().Gy.BitLen() == 0 {
            t.Skip()
            return
        }

        x1, y1 := c.ScalarBaseMult(getK(c))
        if !c.IsOnCurve(x1, y1) {
            t.Fail()
        }
        x2, y2 := c.ScalarBaseMult(getK(c))
        if !c.IsOnCurve(x2, y2) {
            t.Fail()
        }

        x, y := c.Add(x1, y1, x2, y2)
        if !c.IsOnCurve(x, y) {
            t.Fail()
        }
    })
}

func benchmarkAllCurves(b *testing.B, f func(*testing.B, base_elliptic.Curve)) {
    for _, test := range allCurves {
        test := test
        b.Run(test.name, func(B *testing.B) {
            f(b, test.curve)
        })
    }
}

func BenchmarkScalarBaseMult(b *testing.B) {
    benchmarkAllCurves(b, func(b *testing.B, curve base_elliptic.Curve) {
        priv := getK(curve)

        b.ReportAllocs()
        b.ResetTimer()
        for i := 0; i < b.N; i++ {
            x, _ := curve.ScalarBaseMult(priv)
            priv[0] ^= byte(x.Bits()[0])
        }
    })
}

func BenchmarkScalarMult(b *testing.B) {
    benchmarkAllCurves(b, func(b *testing.B, curve base_elliptic.Curve) {
        priv := getK(curve)
        x, y := curve.ScalarBaseMult(priv)

        b.ReportAllocs()
        b.ResetTimer()
        for i := 0; i < b.N; i++ {
            x, y = curve.ScalarMult(x, y, priv)
            priv[0] ^= byte(x.Bits()[0])
        }
    })
}

func BenchmarkDouble(b *testing.B) {
    benchmarkAllCurves(b, func(b *testing.B, curve base_elliptic.Curve) {
        x, y := curve.ScalarBaseMult(getK(curve))

        b.ReportAllocs()
        b.ResetTimer()
        for i := 0; i < b.N; i++ {
            x, y = curve.Double(x, y)
        }
    })
}

func BenchmarkAdd(b *testing.B) {
    benchmarkAllCurves(b, func(b *testing.B, curve base_elliptic.Curve) {
        x1, y1 := curve.ScalarBaseMult(getK(curve))
        x2, y2 := curve.ScalarBaseMult(getK(curve))

        b.ReportAllocs()
        b.ResetTimer()
        for i := 0; i < b.N; i++ {
            x, y := curve.Add(x1, y1, x2, y2)
            x2, y2 = x1, y1
            x1, y1 = x, y
        }
    })
}

// =============

func testCurve(t *testing.T, curve elliptic.Curve) {
    priv, err := ecdsa.GenerateKey(curve, rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    msg := []byte("test")
    r, s, err := ecdsa.Sign(rand.Reader, priv, msg)
    if err != nil {
        t.Fatal(err)
    }

    if !ecdsa.Verify(&priv.PublicKey, msg, r, s) {
        t.Fatal("signature didn't verify.")
    }
}

func TestSect163k1(t *testing.T) {
    testCurve(t, Sect163k1())
}

func TestSect163r1(t *testing.T) {
    testCurve(t, Sect163r1())
}

func TestSect163r2(t *testing.T) {
    testCurve(t, Sect163r2())
}
