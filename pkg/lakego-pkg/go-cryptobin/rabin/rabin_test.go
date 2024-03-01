package rabin

import (
    "io"
    "math/big"
    "crypto/rand"
    "testing"
    "encoding/hex"
)

func encodeHex(src []byte) string {
    return hex.EncodeToString(src)
}

func decodeHex(s string) []byte {
    res, _ := hex.DecodeString(s)
    return res
}

func decodeDec(s string) *big.Int {
    res, _ := new(big.Int).SetString(s, 10)
    return res
}

func Test_GenerateKey(t *testing.T) {
    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    if len(priv.P.Bytes()) == 0 {
        t.Error("fail priv")
    }

    if len(pub.N.Bytes()) == 0 {
        t.Error("fail PublicKey")
    }
}

func Test_NewPrivateKey(t *testing.T) {
    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    priBytes := ToPrivateKey(priv)
    if len(priBytes) == 0 {
        t.Error("fail ToPrivateKey")
    }
    pubBytes := ToPublicKey(pub)
    if len(pubBytes) == 0 {
        t.Error("fail ToPublicKey")
    }

    priv2, err := NewPrivateKey(priBytes)
    if err != nil {
        t.Fatal(err)
    }
    pub2, err := NewPublicKey(pubBytes)
    if err != nil {
        t.Fatal(err)
    }

    if !priv2.Equal(priv) {
        t.Error("NewPrivateKey make fail")
    }

    if !pub2.Equal(pub) {
        t.Error("NewPublicKey make fail")
    }
}

func Test_Encrypt(t *testing.T) {
    message := make([]byte, 8)
    _, err := io.ReadFull(rand.Reader, message)
    if err != nil {
        t.Fatal(err)
    }

    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    endata, err := pub.Encrypt(message, nil)
    if err != nil {
        t.Fatal(err)
    }

    dedata, err := priv.Decrypt(rand.Reader, endata, nil)
    if err != nil {
        t.Fatal(err)
    }

    if string(dedata) != string(message) {
        t.Errorf("fail Decrypt, got %x, want %x", dedata, message)
    }
}
