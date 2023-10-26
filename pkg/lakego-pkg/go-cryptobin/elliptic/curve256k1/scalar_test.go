package curve256k1

import (
    "bytes"
    "math/big"
    "testing"
    "testing/quick"
)

func TestNormalizeScalar(t *testing.T) {
    t.Run("1", func(t *testing.T) {
        x := decodeHex("01")
        want := decodeHex("0000000000000000000000000000000000000000000000000000000000000001")
        got := normalizeScalar(x)
        if !bytes.Equal(got[:], want) {
            t.Errorf("want %x, got %x", want, got)
        }
    })
    t.Run("l-1", func(t *testing.T) {
        x := decodeHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
        want := decodeHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
        got := normalizeScalar(x)
        if !bytes.Equal(got[:], want) {
            t.Errorf("want %x, got %x", want, got)
        }
    })
    t.Run("l", func(t *testing.T) {
        x := decodeHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
        want := decodeHex("0000000000000000000000000000000000000000000000000000000000000000")
        got := normalizeScalar(x)
        if !bytes.Equal(got[:], want) {
            t.Errorf("want %x, got %x", want, got)
        }
    })
    t.Run("l+0x1_45512319_50b75fc4_402da173_2fc9bebf", func(t *testing.T) {
        x := decodeHex("010000000000000000000000000000000000000000000000000000000000000000")
        want := decodeHex("000000000000000000000000000000014551231950b75fc4402da1732fc9bebf")
        got := normalizeScalar(x)
        if !bytes.Equal(got[:], want) {
            t.Errorf("want %x, got %x", want, got)
        }
    })
}

func TestNormalizeScalar_Check(t *testing.T) {
    l, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    f := func(k []byte) bool {
        var want, got [32]byte
        data := new(big.Int).SetBytes(k)
        data.Mod(data, l)
        data.FillBytes(want[:])

        got = normalizeScalar(k)
        return got == want
    }
    if err := quick.Check(f, &quick.Config{MaxCountScale: 1024}); err != nil {
        t.Error(err)
    }
}
