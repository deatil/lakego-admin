package field

import "testing"

func BenchmarkAdd(b *testing.B) {
    var x, y Element
    y.One()
    for i := 0; i < b.N; i++ {
        x.Add(&x, &y)
    }
}

func BenchmarkSub(b *testing.B) {
    var x, y Element
    y.One()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        x.Sub(&x, &y)
    }
}

func BenchmarkNeg(b *testing.B) {
    var x Element
    x.One()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        x.Neg(&x)
    }
}

func BenchmarkMul(b *testing.B) {
    var x, y Element
    y.One()
    x.One()
    x.Add(&x, &x)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        x.Mul(&x, &y)
    }
}

func BenchmarkSquare(b *testing.B) {
    var x Element
    x.One()
    x.Add(&x, &x)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        x.Square(&x)
    }
}

func BenchmarkInv(b *testing.B) {
    var x Element
    x.One()
    x.Add(&x, &x)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        x.Inv(&x)
    }
}
