package ecsdsa

import (
    "strings"
    "crypto"
    "testing"
    "math/big"
    "crypto/rand"
    "crypto/sha256"
    "crypto/sha512"
    "crypto/elliptic"
    "encoding/hex"
    "encoding/pem"
    "encoding/base64"

    "github.com/deatil/go-cryptobin/elliptic/frp256v1"
    "github.com/deatil/go-cryptobin/elliptic/secp256k1"
)

func str(s string) string {
    var sb strings.Builder
    sb.Grow(len(s))
    s = strings.TrimPrefix(s, "0x")
    for _, c := range s {
        switch {
        case '0' <= c && c <= '9':
            sb.WriteRune(c)
        case 'a' <= c && c <= 'f':
            sb.WriteRune(c)
        case 'A' <= c && c <= 'F':
            sb.WriteRune(c)
        }
    }

    return sb.String()
}

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(str(s))
    return h
}

func fromBase64(s string) []byte {
    res, _ := base64.StdEncoding.DecodeString(s)
    return res
}

func toBigint(s string) *big.Int {
    result, _ := new(big.Int).SetString(str(s), 16)

    return result
}

func decodePEM(pubPEM string) []byte {
    block, _ := pem.Decode([]byte(pubPEM))
    if block == nil {
        panic("failed to parse PEM block containing the key")
    }

    return block.Bytes
}

func encodePEM(src []byte, typ string) string {
    keyBlock := &pem.Block{
        Type:  typ,
        Bytes: src,
    }

    keyData := pem.EncodeToMemory(keyBlock)

    return string(keyData)
}

func Test_Interface(t *testing.T) {
    var _ crypto.Signer     = (*PrivateKey)(nil)
    var _ crypto.SignerOpts = (*SignerOpts)(nil)
}

func Test_NewPrivateKey(t *testing.T) {
    p224 := elliptic.P224()

    priv, err := GenerateKey(rand.Reader, p224)
    if err != nil {
        t.Fatal(err)
    }

    privBytes := PrivateKeyTo(priv)
    priv2, err := NewPrivateKey(p224, privBytes)
    if err != nil {
        t.Fatal(err)
    }

    if !priv2.Equal(priv) {
        t.Error("NewPrivateKey Equal error")
    }

    // ======

    pub := &priv.PublicKey

    pubBytes := PublicKeyTo(pub)
    pub2, err := NewPublicKey(p224, pubBytes)
    if err != nil {
        t.Fatal(err)
    }

    if !pub2.Equal(pub) {
        t.Error("NewPublicKey Equal error")
    }
}

func Test_SignerInterface(t *testing.T) {
    priv, err := GenerateKey(rand.Reader, elliptic.P224())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    var _ crypto.Signer = priv
    var _ crypto.PublicKey = pub
}

func Test_SignVerify(t *testing.T) {
    priv, err := GenerateKey(rand.Reader, elliptic.P224())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")

    sig, err := Sign(rand.Reader, priv, sha256.New, data)
    if err != nil {
        t.Fatal(err)
    }

    res := Verify(pub, sha256.New, data, sig)
    if !res {
        t.Error("Verify fail")
    }

}

func Test_SignVerify2(t *testing.T) {
    priv, err := GenerateKey(rand.Reader, elliptic.P224())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")

    sig, err := priv.Sign(rand.Reader, data, &SignerOpts{
        Hash: sha256.New,
    })
    if err != nil {
        t.Fatal(err)
    }

    res, _ := pub.Verify(data, sig, &SignerOpts{
        Hash: sha256.New,
    })
    if !res {
        t.Error("Verify fail")
    }

}

func Test_SignBytes(t *testing.T) {
    t.Run("P224 sha256", func(t *testing.T) {
        test_SignBytes(t, elliptic.P224(), sha256.New)
    })
    t.Run("P256 sha256", func(t *testing.T) {
        test_SignBytes(t, elliptic.P256(), sha256.New)
    })
    t.Run("P384 sha256", func(t *testing.T) {
        test_SignBytes(t, elliptic.P384(), sha256.New)
    })
    t.Run("P384 sha384", func(t *testing.T) {
        test_SignBytes(t, elliptic.P384(), sha512.New384)
    })
    t.Run("P384 sha512", func(t *testing.T) {
        test_SignBytes(t, elliptic.P384(), sha512.New)
    })
    t.Run("P521 sha256", func(t *testing.T) {
        test_SignBytes(t, elliptic.P521(), sha256.New)
    })

    t.Run("FRP256v1 sha256", func(t *testing.T) {
        test_SignBytes(t, frp256v1.FRP256v1(), sha256.New)
    })
    t.Run("S256 sha256", func(t *testing.T) {
        test_SignBytes(t, secp256k1.S256(), sha256.New)
    })
}

func test_SignBytes(t *testing.T, c elliptic.Curve, h Hasher) {
    priv, err := GenerateKey(rand.Reader, c)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    data := []byte("test-data test-data test-data test-data test-data")

    sig, err := SignBytes(rand.Reader, priv, h, data)
    if err != nil {
        t.Fatal(err)
    }

    res := VerifyBytes(pub, h, data, sig)
    if !res {
        t.Error("Verify fail")
    }

}
