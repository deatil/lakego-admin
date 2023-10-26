package field

import "testing"

func BenchmarkAdd(b *testing.B) {
    var x, y Element
    x.One()
    y.Add(feOne, feOne)
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        x.Add(&x, &y)
    }
}

func BenchmarkSub(b *testing.B) {
    var x, y Element
    x.One()
    y.Add(feOne, feOne)
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        x.Sub(&x, &y)
    }
}

func BenchmarkNegate(b *testing.B) {
    var x Element
    x.One()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        x.Negate(&x)
    }
}

func BenchmarkSetBytes(b *testing.B) {
    var x Element
    data := []byte{
        0x56, 0x67, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    }
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        x.SetBytes(data)
    }
}

func BenchmarkEqual1(b *testing.B) {
    x := &Element{1, 1, 1, 1, 1, 1, 1, 1}
    y := &Element{8, 7, 6, 5, 4, 3, 2, 1}
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        x.Equal(y)
    }
}

func BenchmarkEqual2(b *testing.B) {
    x := &Element{1, 1, 1, 1, 1, 1, 1, 1}
    y := &Element{1, 1, 1, 1, 1, 1, 1, 1}
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        x.Equal(y)
    }
}

func BenchmarkMul32(b *testing.B) {
    var x Element
    x.One()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        x.Mul32(&x, 2)
    }
}

func BenchmarkMul(b *testing.B) {
    var x, y Element
    x.One()
    y.Add(feOne, feOne)
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        x.Mul(&x, &y)
    }
}

func BenchmarkSquare(b *testing.B) {
    var x Element
    x.One()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        x.Square(&x)
    }
}

func BenchmarkInv(b *testing.B) {
    var x Element
    x.One()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        x.Inv(&x)
    }
}

func BenchmarkSqrtRatio(b *testing.B) {
    var u Element
    var v Element
    u.One()
    v.One()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        u.SqrtRatio(&u, &v)
    }
}
