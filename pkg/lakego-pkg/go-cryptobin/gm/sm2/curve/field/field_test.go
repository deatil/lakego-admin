package field_test

import (
    "testing"

    "github.com/deatil/go-cryptobin/gm/sm2/curve/field"
)

func BenchmarkMul(b *testing.B) {
    v := new(field.Element).One()
    b.ReportAllocs()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        v.Mul(v, v)
    }
}

func BenchmarkSquare(b *testing.B) {
    v := new(field.Element).One()
    b.ReportAllocs()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        v.Square(v)
    }
}
