package gost34112012256

import (
    "fmt"
    "hash"
    "testing"
    "crypto/hmac"
    "encoding/hex"
    "encoding/binary"
)

func TestHashInterface(t *testing.T) {
    h := New()
    var _ hash.Hash = h
}

func TestHashed(t *testing.T) {
    h := New()
    m := make([]byte, BlockSize)
    for i := 0; i < BlockSize; i++ {
        m[i] = byte(i)
    }

    h.Write(m)
    hashed := h.Sum(nil)

    if len(hashed) == 0 {
        t.Error("Hash error")
    }
}

func Test_ESPTree(t *testing.T) {
    data := NewESPTree([]byte("rgtf5yds")).Derive([]byte("olkpj"))

    if len(data) == 0 {
        t.Error("ESPTree data error")
    }
}

func Test_TLSTree(t *testing.T) {
    num := binary.BigEndian.Uint64([]byte{0xFE, 0xFF, 0xFF, 0xC0, 0x00, 0x00, 0x00, 0x00})

    data := NewTLSTree(TLSKuznyechikCTROMAC, []byte("rgtf5yds")).Derive(num)

    if len(data) == 0 {
        t.Error("TLSTree data error")
    }
}

func Test_Check(t *testing.T) {
    in := []byte("nonce-asdfg123123123")
    check := "f24a63bbb863ba538ad956ababb0c4a651136a4d81c878a818bad28c9094d8e1"

    h := New()
    h.Write(in)

    out := h.Sum(nil)

    if fmt.Sprintf("%x", out) != check {
        t.Errorf("Check error. got %x, want %s", out, check)
    }
}

func Test_Check_2(t *testing.T) {
    in, _ := hex.DecodeString("0126bdb87800af214341456563780100")
    key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    check := "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"

    mac := hmac.New(New, key)
    mac.Write(in)
    out := mac.Sum(nil)

    if fmt.Sprintf("%x", out) != check {
        t.Errorf("Check 2 error. got %x, want %s", out, check)
    }
}

func Test_Check_3(t *testing.T) {
    check := "e3c9fd89226d93b489a9fe27d686806e24a514e3787bca053c698ec4616ceb78"

    mac := New()
    mac.Write([]byte("foo"))
    mac.Write([]byte("bar"))

    out := mac.Sum(nil)

    if fmt.Sprintf("%x", out) != check {
        t.Errorf("Check 3 error. got %x, want %s", out, check)
    }
}

func reverse(b []byte) []byte {
    d := make([]byte, len(b))
    copy(d, b)

    for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
        d[i], d[j] = d[j], d[i]
    }

    return d
}

func Test_Check_Vectors(t *testing.T) {
    t.Run("test_m1", func(t *testing.T) {
        in, _ := hex.DecodeString("323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130")
        check := "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d"

        h := New()
        h.Write(reverse(in))
        out := h.Sum(nil)

        if fmt.Sprintf("%x", reverse(out)) != check {
            t.Errorf("Check_Vectors error. got %x, want %s", out, check)
        }
    })

    t.Run("test_m2", func(t *testing.T) {
        in, _ := hex.DecodeString("fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1")
        check := "508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d"

        h := New()
        h.Write(reverse(in))
        out := h.Sum(nil)

        if fmt.Sprintf("%x", reverse(out)) != check {
            t.Errorf("Check_Vectors error. got %x, want %s", out, check)
        }
    })

    t.Run("test_habr144", func(t *testing.T) {
        in, _ := hex.DecodeString("d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff0900060000000000000000000000010000000100000000000000001000002400000001000000feffffff0000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        check := "c766085540caaa8953bfcf7a1ba220619cee50d65dc242f82f23ba4b180b18e0"

        h := New()
        h.Write(in)
        out := h.Sum(nil)

        if fmt.Sprintf("%x", out) != check {
            t.Errorf("Check_Vectors error. got %x, want %s", out, check)
        }
    })
}
