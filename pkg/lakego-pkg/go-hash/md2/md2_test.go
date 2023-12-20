package md2

import (
    "fmt"
    "testing"
)

func Test_Check(t *testing.T) {
    in := []byte("nonce-asdfg")
    check := "b964b13bcf98269d49356894e7849374"

    h := New()
    h.Write(in)

    out := h.Sum(nil)

    if fmt.Sprintf("%x", out) != check {
        t.Errorf("Check error. got %x, want %s", out, check)
    }
}
