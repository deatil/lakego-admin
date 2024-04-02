package haraka

import (
    "fmt"
    "testing"
    "testing/quick"
)

var (
    // test vectors from Appendix B
    haraka512TestIn = [64]byte{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    }
    haraka512TestOut = [32]byte{
        0xbe, 0x7f, 0x72, 0x3b, 0x4e, 0x80, 0xa9, 0x98, 0x13, 0xb2, 0x92, 0x28, 0x7f, 0x30, 0x6f, 0x62,
        0x5a, 0x6d, 0x57, 0x33, 0x1c, 0xae, 0x5f, 0x34, 0xdd, 0x92, 0x77, 0xb0, 0x94, 0x5b, 0xe2, 0xaa,
    }
    haraka256TestIn = [32]byte{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    }
    haraka256TestOut = [32]byte{
        0x80, 0x27, 0xcc, 0xb8, 0x79, 0x49, 0x77, 0x4b, 0x78, 0xd0, 0x54, 0x5f, 0xb7, 0x2b, 0xf7, 0x0c,
        0x69, 0x5c, 0x2a, 0x09, 0x23, 0xcb, 0xd4, 0x7b, 0xba, 0x11, 0x59, 0xef, 0xbf, 0x2b, 0x2c, 0x1c,
    }
)

func TestHaraka256(t *testing.T) {
    in := haraka256TestIn
    want := &haraka256TestOut
    got := Haraka256(in)
    for i := range got {
        if got[i] != want[i] {
            t.Errorf("got:  %x\nwant: %x", got, want)
            break
        }
    }
}

func TestHaraka256Ref(t *testing.T) {
    in := &haraka256TestIn
    got := new([32]byte)
    want := &haraka256TestOut
    haraka256Ref(got, in)
    for i := range got {
        if got[i] != want[i] {
            t.Errorf("got:  %x\nwant: %x", got, want)
            break
        }
    }
}

func TestHaraka256Consistent(t *testing.T) {
    f := func(x [32]byte) string {
        dst := Haraka256(x)
        return fmt.Sprintf("%0x", dst)
    }
    g := func(x [32]byte) string {
        dst := new([32]byte)
        haraka256Ref(dst, &x)
        return fmt.Sprintf("%0x", *dst)
    }
    if err := quick.CheckEqual(f, g, nil); err != nil {
        t.Error(err)
    }
}

func TestHaraka512(t *testing.T) {
    in := haraka512TestIn
    want := &haraka512TestOut
    got := Haraka512(in)
    for i := range got {
        if got[i] != want[i] {
            t.Errorf("got:  %x\nwant: %x", got, want)
            break
        }
    }
}

func TestHaraka512Ref(t *testing.T) {
    in := &haraka512TestIn
    got := new([32]byte)
    want := &haraka512TestOut
    haraka512Ref(got, in)
    for i := range got {
        if got[i] != want[i] {
            t.Errorf("got:  %x\nwant: %x", got, want)
            break
        }
    }
}

func TestHaraka512Consistent(t *testing.T) {
    f := func(x [64]byte) string {
        dst := Haraka512(x)
        return fmt.Sprintf("%0x", dst)
    }
    g := func(x [64]byte) string {
        dst := new([32]byte)
        haraka512Ref(dst, &x)
        return fmt.Sprintf("%0x", *dst)
    }
    if err := quick.CheckEqual(f, g, nil); err != nil {
        t.Error(err)
    }
}

func BenchmarkHaraka256(b *testing.B) {
    var in [32]byte
    for i := 0; i < b.N; i++ {
        Haraka256(in)
    }
}

func BenchmarkHaraka512(b *testing.B) {
    var in [64]byte

    for i := 0; i < b.N; i++ {
        Haraka512(in)
    }
}

func BenchmarkHaraka256Ref(b *testing.B) {
    var in [32]byte
    prev := hasAES
    hasAES = false
    for i := 0; i < b.N; i++ {
        Haraka256(in)
    }

    hasAES = prev
}

func BenchmarkHaraka512Ref(b *testing.B) {
    var in [64]byte
    prev := hasAES
    hasAES = false
    for i := 0; i < b.N; i++ {
        Haraka512(in)
    }
    hasAES = prev
}
