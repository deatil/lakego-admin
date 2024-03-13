package cubehash

import (
    "bytes"
    "encoding"
    "fmt"
    "testing"
)

func TestSum(t *testing.T) {
    table := []struct {
        in   string
        want string
    }{
        {
            "",
            "37045cca405ee6fbdf815ed8b57c971b" +
                "b78dafb58f3ef676c977a716f66dbd8f" +
                "376fef59d2e0687cf5608c5dad53ba42" +
                "c8456269f3f3bcfb27d9b75caaa26e11",
        },
        {
            "Hello",
            "a3c2b3d38c940b46b51c286b0159bceb" +
                "34fa7ae4d307234f48a2ca4662a21ddc" +
                "5875fda2c2a5994bb4d45dbbb3218381" +
                "174d5dd5f0aae87db87d086dff46e3ae",
        },
        {
            "The quick brown fox jumped over the lazy dog.",
            "8be880e82d924eaa4c569758429c9edf" +
                "93f178b8ad078650c56fa02afd7d8213" +
                "fa3b0da03f75f866c82c24a206ef0709" +
                "775d1a11813b56075b1aaa29480e1060",
        },
    }

    c := New()
    for _, r := range table {
        c.Reset()
        c.Write([]byte(r.in))
        got := fmt.Sprintf("%x", c.Sum(nil))
        if got != r.want {
            t.Errorf("Sum(%#v), got %#v, want %#v", r.in, got, r.want)
        }
    }

    for _, r := range table {
        c := New()
        for _, b := range []byte(r.in) {
            // byte at at time test
            c.Write([]byte{b})
        }
        got := fmt.Sprintf("%x", c.Sum(nil))
        if got != r.want {
            t.Errorf("Sum(%#v)b, got %#v, want %#v", r.in, got, r.want)
        }

        got2 := fmt.Sprintf("%x", c.Sum(nil))
        if got != got2 {
            t.Errorf("repeat Sum(), got %#v, want %#v", got2, got)
        }
    }
}

func TestMarshal(t *testing.T) {
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
