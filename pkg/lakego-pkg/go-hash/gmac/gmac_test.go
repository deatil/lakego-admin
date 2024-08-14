package gmac

import (
    "bytes"
    "testing"
    "crypto/aes"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func Test_GMAC_Check(t *testing.T) {
    // https://cryptopp.com/wiki/GMAC
    var (
        key    = fromHex(`00000000000000000000000000000000`)
        iv     = fromHex(`00000000000000000000000000000000`)
        msg    = []byte(`Yoda said, do or do not. There is no try.`)
        expect = fromHex(`E7EE2C63B4DC328EED4A86B3FB3490AF`)
    )

    c, err := aes.NewCipher(key)
    if err != nil {
        t.Fatal(err)
    }

    h, err := New(c, iv)
    if err != nil {
        t.Fatal(err)
    }

    h.Write(msg)
    actual := h.Sum(nil)
    if !bytes.Equal(actual, expect) {
        t.Errorf("want: %x, got: %x", expect, actual)
        return
    }

    h.Reset()
    h.Write(msg)
    actual = h.Sum(actual[:0])
    if !bytes.Equal(actual, expect) {
        t.Errorf("want: %x, got: %x", expect, actual)
        return
    }
}
