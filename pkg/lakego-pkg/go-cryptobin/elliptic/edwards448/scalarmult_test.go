package edwards448

import (
    "testing"
)

func TestScalarBaseMult(t *testing.T) {
    t.Run("positive", func(t *testing.T) {
        s := new(Scalar)
        g := NewGeneratorPoint()
        want := new(Point).Zero()
        for i := 0; i <= 1024; i++ {
            got := new(Point).ScalarBaseMult(s)
            if got.Equal(want) == 0 {
                t.Errorf("%d: got %#v, want %#v", i, got.Bytes(), want.Bytes())
            }
            s.Add(s, &scOne)
            want.Add(want, g)
        }
    })

    t.Run("negative", func(t *testing.T) {
        s := new(Scalar)
        g := NewGeneratorPoint()
        want := new(Point).Zero()
        for i := 0; i <= 1024; i++ {
            got := new(Point).ScalarBaseMult(s)
            if got.Equal(want) == 0 {
                t.Errorf("%d, got %#v, want %#v", -i, got.Bytes(), want.Bytes())
            }
            s.Sub(s, &scOne)
            want.Sub(want, g)
        }
    })
}

func BenchmarkScalarBaseMult1(b *testing.B) {
    s := new(Scalar).Set(&scOne)
    var p Point
    for i := 0; i < b.N; i++ {
        p.ScalarBaseMult(s)
    }
}

func BenchmarkScalarBaseMultMinus1(b *testing.B) {
    s := new(Scalar).Set(&scMinusOne)
    var p Point
    for i := 0; i < b.N; i++ {
        p.ScalarBaseMult(s)
    }
}

func TestScalarMult(t *testing.T) {
    t.Run("positive", func(t *testing.T) {
        s := new(Scalar)
        g := NewGeneratorPoint()
        want := new(Point).Zero()
        for i := 0; i <= 1024; i++ {
            got := new(Point).ScalarMult(s, g)
            if got.Equal(want) == 0 {
                t.Errorf("%d: got %#v, want %#v", i, got.Bytes(), want.Bytes())
            }
            s.Add(s, &scOne)
            want.Add(want, g)
        }
    })

    t.Run("negative", func(t *testing.T) {
        s := new(Scalar)
        g := NewGeneratorPoint()
        want := new(Point).Zero()
        for i := 0; i <= 1024; i++ {
            got := new(Point).ScalarMult(s, g)
            if got.Equal(want) == 0 {
                t.Errorf("%d, got %#v, want %#v", -i, got.Bytes(), want.Bytes())
            }
            s.Add(s, &scMinusOne)
            want.Sub(want, g)
        }
    })
}

func BenchmarkScalarMult1(b *testing.B) {
    s := new(Scalar).Set(&scOne)
    p := NewGeneratorPoint()
    for i := 0; i < b.N; i++ {
        p.ScalarMult(s, p)
    }
}

func BenchmarkScalarMultMinus1(b *testing.B) {
    s := new(Scalar).Set(&scMinusOne)
    p := NewGeneratorPoint()
    for i := 0; i < b.N; i++ {
        p.ScalarMult(s, p)
    }
}

func TestVarTimeDoubleScalarBaseMult(t *testing.T) {
    t.Run("positive", func(t *testing.T) {
        a := new(Scalar)
        b := new(Scalar)
        p := NewIdentityPoint()
        g := NewGeneratorPoint()
        want := new(Point).Zero()
        for i := 0; i <= 1024; i++ {
            got := new(Point).VarTimeDoubleScalarBaseMult(a, p, b)
            if got.Equal(want) == 0 {
                t.Errorf("%d: got %#v, want %#v", i, got.Bytes(), want.Bytes())
            }
            a.Add(a, &scOne)
            b.Add(b, &scMinusOne)
            want.Add(want, p)
            want.Sub(want, g)
        }
    })

    t.Run("negative", func(t *testing.T) {
        a := new(Scalar)
        b := new(Scalar)
        p := NewIdentityPoint()
        g := NewGeneratorPoint()
        want := new(Point).Zero()
        for i := 0; i <= 1024; i++ {
            got := new(Point).VarTimeDoubleScalarBaseMult(a, p, b)
            if got.Equal(want) == 0 {
                t.Errorf("%d: got %#v, want %#v", i, got.Bytes(), want.Bytes())
            }
            a.Add(a, &scMinusOne)
            b.Add(b, &scOne)
            want.Sub(want, p)
            want.Add(want, g)
        }
    })
}

func BenchmarkVarTimeDoubleScalarBaseMult1(b *testing.B) {
    s := new(Scalar).Set(&scOne)
    p := NewGeneratorPoint()
    for i := 0; i < b.N; i++ {
        p.VarTimeDoubleScalarBaseMult(s, p, s)
    }
}

func BenchmarkVarTimeDoubleScalarBaseMultMinus1(b *testing.B) {
    s := new(Scalar).Set(&scMinusOne)
    p := NewGeneratorPoint()
    for i := 0; i < b.N; i++ {
        p.VarTimeDoubleScalarBaseMult(s, p, s)
    }
}
