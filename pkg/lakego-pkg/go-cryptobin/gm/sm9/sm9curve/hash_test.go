package sm9curve

import (
    "testing"
)

var buf = make([]byte, 8192)

func benchmarkSize(b *testing.B, size int) {
    b.SetBytes(int64(size))
    for i := 0; i < b.N; i++ {
        HashG1(buf[:size], nil)
    }
}

func BenchmarkHashG1Size8bytes(b *testing.B) {
    b.ResetTimer()
    benchmarkSize(b, 8)
}

func BenchmarkHashG1Size1k(b *testing.B) {
    b.ResetTimer()
    benchmarkSize(b, 1024)
}

func BenchmarkHashG1Size8k(b *testing.B) {
    b.ResetTimer()
    benchmarkSize(b, 8192)
}
