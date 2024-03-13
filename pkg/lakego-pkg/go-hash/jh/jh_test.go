package jh

import (
    "fmt"
    "testing"
)

func Test_Check(t *testing.T) {
    in := []byte("nonce-asdfg")
    check := "84bcd622325787f4096e4aae5fbec20f1dd041ba22785a2e49d9b9ad0f976afa"

    h := New()
    h.Write(in)

    out := h.Sum(nil)

    if fmt.Sprintf("%x", out) != check {
        t.Errorf("Check error. got %x, want %s", out, check)
    }

    // ==========

    out2 := Sum(in)

    if fmt.Sprintf("%x", out2) != check {
        t.Errorf("Check error. got %x, want %s", out2, check)
    }
}
