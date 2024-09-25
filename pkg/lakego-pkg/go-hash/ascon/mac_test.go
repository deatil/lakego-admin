package ascon

import (
    "fmt"
    "testing"
)

func TestMAC(t *testing.T) {
    want := "EB1AF688825D66BF2D53E135F9323315"
    mk := func(n int) []byte {
        b := make([]byte, n)
        for i := range b {
            b[i] = byte(i % 256)
        }
        return b
    }
    m := NewMAC(mk(16))
    got := fmt.Sprintf("%X", m.Sum(nil))
    if got != want {
        t.Errorf("got %s, want %s", got, want)
    }

    if ok := m.Verify(fromHex(want)); ok != true {
        t.Errorf("Verify(mac) = %t, want %t", ok, true)
    }
    if ok := m.Verify(mk(16)); ok != false {
        t.Errorf("Verify(bad mac) = %t, want %t", ok, false)
    }
}
