package tiger128

import (
    "fmt"
    "testing"
)

func Test_New_Check(t *testing.T) {
    in := []byte("nonce-asdfg")
    check := "fa3bf582c8c148bc1721831e7c837ae2"

    h := New()
    h.Write(in)

    out := h.Sum(nil)

    if fmt.Sprintf("%x", out) != check {
        t.Errorf("Check error. got %x, want %s", out, check)
    }
}

func Test_New2_Check(t *testing.T) {
    in := []byte("nonce-asdfg")
    check := "1dc1628ef2db5cc769421ad7ac509a64"

    h := New2()
    h.Write(in)

    out := h.Sum(nil)

    if fmt.Sprintf("%x", out) != check {
        t.Errorf("Check error. got %x, want %s", out, check)
    }
}
