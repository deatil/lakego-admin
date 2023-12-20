package gost34112012512

import (
    "fmt"
    "testing"
)

func Test_Check(t *testing.T) {
    in := []byte("gost34112012512-asdfg")
    check := "f6e5e348001a4ee3a1299c5283ddae617655353fcfc3d79c81f9c01470bbef58075b0514c0b03187a3c1bb7a24383664abac0fbc2019555ec65b9a7d972bf864"

    h := New()
    h.Write(in)

    out := h.Sum(nil)

    if fmt.Sprintf("%x", out) != check {
        t.Errorf("Check error. got %x, want %s", out, check)
    }
}
