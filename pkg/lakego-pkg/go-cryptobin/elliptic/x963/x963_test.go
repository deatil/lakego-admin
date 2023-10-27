package x963

import (
    "bufio"
    "crypto/rand"
    "math/big"
    "testing"

    "github.com/deatil/go-cryptobin/elliptic/base_elliptic"
)

var (
    allCurves = []struct {
        name  string
        curve base_elliptic.Curve
    }{
        {"ansit163k1", Ansit163k1()},
        {"ansit163r1", Ansit163r1()},
        {"ansit163r2", Ansit163r2()},
        {"ansit193r1", Ansit193r1()},
        {"ansit193r2", Ansit193r2()},
        {"ansit233k1", Ansit233k1()},
        {"ansit233r1", Ansit233r1()},
        {"ansit239k1", Ansit239k1()},
        {"ansit283k1", Ansit283k1()},
        {"ansit283r1", Ansit283r1()},
        {"ansit409k1", Ansit409k1()},
        {"ansit409r1", Ansit409r1()},
        {"ansit571k1", Ansit571k1()},
        {"ansit571r1", Ansit571r1()},
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
