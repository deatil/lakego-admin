package tiger160

import (
    "fmt"
    "testing"
)

func Test_New_Check(t *testing.T) {
    in := []byte("nonce-asdfg")
    check := "fa3bf582c8c148bc1721831e7c837ae2933fb670"

    h := New()
    h.Write(in)

    out := h.Sum(nil)

    if fmt.Sprintf("%x", out) != check {
        t.Errorf("Check error. got %x, want %s", out, check)
    }
}

func Test_New2_Check(t *testing.T) {
    in := []byte("nonce-asdfg")
    check := "1dc1628ef2db5cc769421ad7ac509a642f66f22a"

    h := New2()
    h.Write(in)

    out := h.Sum(nil)

    if fmt.Sprintf("%x", out) != check {
        t.Errorf("Check error. got %x, want %s", out, check)
    }
}
