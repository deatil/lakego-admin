package skein512

import (
    "bytes"
    "testing"
    "encoding/hex"
)

func fromHex(s string) []byte {
    ret, err := hex.DecodeString(s)
    if err != nil {
        panic(err)
    }
    return ret
}

func Test_Check(t *testing.T) {
    key := []byte("key")
    nonce := []byte("nonce")
    in := make([]byte, 10)
    check := fromHex("ed036a52bbb40f471c77")
    out := make([]byte, 10)

    c := NewCipher(key, nonce)
    c.XORKeyStream(out, in)

    if !bytes.Equal(out, check) {
        t.Errorf("fail: got %x, want %x", out, check)
    }

    // ==========

    out2 := make([]byte, 10)

    c2 := NewCipher(key, nonce)
    c2.XORKeyStream(out2, out)

    if !bytes.Equal(out2, in) {
        t.Errorf("fail: got %x, want %x", out2, in)
    }
}

func xorInPortions(key, nonce, b []byte) {
    c := NewCipher(key, nonce)
    i := 1
    for {
        c.XORKeyStream(b[:i], b[:i])
        b = b[i:]
        i *= 3
        if i >= len(b) {
            c.XORKeyStream(b, b)
            break
        }
    }

}

func Test_NewCipher(t *testing.T) {
    key := []byte("key")
    nonce := []byte("nonce")
    in := make([]byte, 3045)
    for i := range in {
        in[i] = byte(i)
    }

    // Encrypt in portions.
    xorInPortions(key, nonce, in)

    // Decrypt whole buffer.
    c := NewCipher(key, nonce)
    c.XORKeyStream(in, in)

    for i, v := range in {
        if v != byte(i) {
            t.Fatalf("byte at %d: expected %x, got %x", i, byte(i), v)
        }
    }
}
