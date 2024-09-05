package rabin

import (
    "io"
    "fmt"
    "time"
    "bytes"
    "testing"
    "math/big"
    "crypto/rand"
    "encoding/hex"
    math_rand "math/rand"
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

    priBytes := PrivateKeyTo(priv)
    if len(priBytes) == 0 {
        t.Error("fail PrivateKeyTo")
    }
    pubBytes := PublicKeyTo(pub)
    if len(pubBytes) == 0 {
        t.Error("fail PublicKeyTo")
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

func getRandNum(min, max int) int {
    math_rand.Seed(time.Now().UnixNano())
    return math_rand.Intn(max - min + 1) + min
}

func Test_Encrypt(t *testing.T) {
    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    max := 100

    for i := 0; i < max; i++ {
        t.Run(fmt.Sprintf("Test %d", i), func(t *testing.T) {
            message := make([]byte, getRandNum(8, 80))
            _, err = io.ReadFull(rand.Reader, message)
            if err != nil {
                t.Fatal(err)
            }

            endata, err := pub.Encrypt(message, nil)
            if err != nil {
                t.Fatal(err)
            }

            dedata, err := priv.Decrypt(rand.Reader, endata, nil)
            if err != nil {
                t.Fatal(err)
            }

            if bytes.Compare(dedata, message) != 0 {
                t.Errorf("fail Decrypt, got %x, want %x", dedata, message)
            }
        })
    }
}

func Test_Bytes(t *testing.T) {
    a := []byte("abcdef")
    b := []byte("abcdef")

    b = append([]byte{byte(0)}, b...)

    p := new(big.Int).SetBytes(b)
    b = p.Bytes()

    if bytes.Compare(a, b) != 0 {
        t.Errorf("got %x, want %x", a, b)
    }
}

func Test_Encrypt_FillBytes(t *testing.T) {
    priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    message := []byte("abcdef")
    message = append([]byte{byte(0), byte(0), byte(0)}, message...)

    endata, err := pub.Encrypt(message, nil)
    if err != nil {
        t.Fatal(err)
    }

    dedata, err := priv.Decrypt(rand.Reader, endata, nil)
    if err != nil {
        t.Fatal(err)
    }

    if bytes.Compare(dedata, message) != 0 {
        t.Errorf("fail Decrypt, got %x, want %x", dedata, message)
    }
}
