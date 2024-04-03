package cubehash256

import (
    "fmt"
    "hash"
    "bytes"
    "encoding"
    "testing"
)

func Test_Interfaces(t *testing.T) {
    // digest
    var _ hash.Hash = (*digest)(nil)
    var _ encoding.BinaryMarshaler = (*digest)(nil)
    var _ encoding.BinaryUnmarshaler = (*digest)(nil)
}

func Test_Sum(t *testing.T) {
    msg := "78AECC1F4DBF27AC146780EEA8DCC56B"
    check := "df8c13ad710ba02a0a293b94e144d3b212bbf37cbf51c17e0716f65126a23621"

    dst := Sum([]byte(msg))

    if fmt.Sprintf("%x", dst) != check {
        t.Errorf("fail, got %x, want %s", dst, check)
    }

}

func Test_Marshal(t *testing.T) {
    a := New()
    a.Write([]byte{1, 2, 3})
    save, _ := a.(encoding.BinaryMarshaler).MarshalBinary()

    b := New()
    b.(encoding.BinaryUnmarshaler).UnmarshalBinary(save)

    asum := a.Sum(nil)
    bsum := b.Sum(nil)
    if !bytes.Equal(asum, bsum) {
        t.Errorf("UnmarshalBinary(...), got %x, want %x", bsum, asum)
    }
}

func BenchmarkSum(b *testing.B) {
    var buf [1 << 20]byte
    c := New()
    for i := 0; i < b.N; i++ {
        c.Reset()
        c.Write(buf[:])
        c.Sum(nil)
    }
}
