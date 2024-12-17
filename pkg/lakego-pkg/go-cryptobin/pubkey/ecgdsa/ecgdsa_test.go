package ecgdsa

import (
    "fmt"
    "strings"
    "crypto"
    "testing"
    "math/big"
    "crypto/rand"
    "crypto/sha256"
    "crypto/elliptic"
    "encoding/hex"
    "encoding/pem"
    "encoding/base64"

    "github.com/deatil/go-cryptobin/elliptic/brainpool"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
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
    t.Run("P521 sha256", func(t *testing.T) {
        test_SignBytes(t, elliptic.P521(), sha256.New)
    })

    t.Run("brainpool P256r1 sha256", func(t *testing.T) {
        test_SignBytes(t, brainpool.P256r1(), sha256.New)
    })
    t.Run("brainpool P256t1 sha256", func(t *testing.T) {
        test_SignBytes(t, brainpool.P256t1(), sha256.New)
    })
    t.Run("brainpool P320r1 sha256", func(t *testing.T) {
        test_SignBytes(t, brainpool.P320r1(), sha256.New)
    })
    t.Run("brainpool P320t1 sha256", func(t *testing.T) {
        test_SignBytes(t, brainpool.P320t1(), sha256.New)
    })
    t.Run("brainpool P384r1 sha256", func(t *testing.T) {
        test_SignBytes(t, brainpool.P384r1(), sha256.New)
    })
    t.Run("brainpool P384t1 sha256", func(t *testing.T) {
        test_SignBytes(t, brainpool.P384t1(), sha256.New)
    })
    t.Run("brainpool P512r1 sha256", func(t *testing.T) {
        test_SignBytes(t, brainpool.P512r1(), sha256.New)
    })
    t.Run("brainpool P512t1 sha256", func(t *testing.T) {
        test_SignBytes(t, brainpool.P512t1(), sha256.New)
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

func Test_Marshal(t *testing.T) {
    private, err := GenerateKey(rand.Reader, elliptic.P224())
    if err != nil {
        t.Fatal(err)
    }

    public := &private.PublicKey

    pubkey, err := MarshalPublicKey(public)
    if err != nil {
        t.Errorf("MarshalPublicKey error: %s", err)
    }

    parsedPub, err := ParsePublicKey(pubkey)
    if err != nil {
        t.Errorf("ParsePublicKey error: %s", err)
    }

    prikey, err := MarshalPrivateKey(private)
    if err != nil {
        t.Errorf("MarshalPrivateKey error: %s", err)
    }

    parsedPri, err := ParsePrivateKey(prikey)
    if err != nil {
        t.Errorf("ParsePrivateKey error: %s", err)
    }

    if !public.Equal(parsedPub) {
        t.Errorf("parsedPub error")
    }
    if !private.Equal(parsedPri) {
        t.Errorf("parsedPri error")
    }
}

var privPEM = `-----BEGIN PRIVATE KEY-----
MHkCAQAwEQYIKyQDAwIFAgEGBSuBBAAhBGEwXwIBAQQcCfFwyIMzdjIApZTyz7Au
FHDpX3hLELLj+WtAgKE8AzoABJhqzD2woCYdBy4kBOYyed725vjPH2lgkxdXyvqK
2bQylAFmE2/VlOmblEwZxGoEJVxbgckOvuHL
-----END PRIVATE KEY-----
`

var pubPEM = `-----BEGIN PUBLIC KEY-----
ME8wEQYIKyQDAwIFAgEGBSuBBAAhAzoABILd0VpnGfuYjhu0rBD6HF6F6YYmKJTe
AO3FivH8Fzlf3PpdkYCPs2mxQozfNYcwpIvfcCAI3dF4
-----END PUBLIC KEY-----
`

func Test_Marshal_Check(t *testing.T) {
    test_Marshal_Check(t, privPEM, pubPEM)
}

func test_Marshal_Check(t *testing.T, priv, pub string) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    parsedPub, err := ParsePublicKey(decodePEM(pub))
    if err != nil {
        t.Errorf("ParsePublicKey error: %s", err)
    }

    pubkey, err := MarshalPublicKey(parsedPub)
    if err != nil {
        t.Errorf("MarshalPublicKey error: %s", err)
    }

    pubPemCheck := encodePEM(pubkey, "PUBLIC KEY")
    assertEqual(pubPemCheck, pub, "test_Marshal_Check pubkey")

    // ===========

    parsedPriv, err := ParsePrivateKey(decodePEM(priv))
    if err != nil {
        t.Errorf("ParsePrivateKey error: %s", err)
    }

    privkey, err := MarshalPrivateKey(parsedPriv)
    if err != nil {
        t.Errorf("MarshalPrivateKey error: %s", err)
    }

    privPemCheck := encodePEM(privkey, "PRIVATE KEY")
    assertEqual(privPemCheck, priv, "test_Marshal_Check privkey")
}

func Test_PKCS8PrivateKey_Check(t *testing.T) {
    for i, tc := range ecgdsaTestCases {
        t.Run(fmt.Sprintf("EC-GDSA index %d", i), func(t *testing.T) {
            expectedDER := decodePEM(tc.pkcs8PrivateKey)

            prikey, err := ParsePrivateKey(expectedDER)
            if err != nil {
                t.Error(err)
                return
            }

            pubDER := decodePEM(tc.pkixPublicKey)
            pubkey, err := ParsePublicKey(pubDER)
            if err != nil {
                t.Error(err)
                return
            }

            parsePubkey := &prikey.PublicKey

            if !pubkey.Equal(parsePubkey) {
                t.Errorf("ParsePKCS8PrivateKey fail")
                return
            }

            res := Verify(pubkey, sha256.New, []byte(tc.msg), tc.sig)
            if !res {
                t.Error("Verify fail")
                return
            }

            {
                sig, err := Sign(rand.Reader, prikey, sha256.New, []byte(tc.msg))
                if err != nil {
                    t.Error(err)
                    return
                }

                res := Verify(pubkey, sha256.New, []byte(tc.msg), sig)
                if !res {
                    t.Error("Verify 2 fail")
                    return
                }
            }

        })
    }

}

// botan 3.6.0
var ecgdsaTestCases = []struct {
    pkcs8PrivateKey string
    pkixPublicKey   string
    msg             string
    sig             []byte
}{
    // botan keygen --algo=ECGDSA --params=secp224r1 | tee priv.pem; botan pkcs8 --pub-out priv.pem | tee pub.pem
    {
        pkcs8PrivateKey: `-----BEGIN PRIVATE KEY-----
MHkCAQAwEQYIKyQDAwIFAgEGBSuBBAAhBGEwXwIBAQQchiYDBE//3ic1+4+qz1ft
0WrUqSLYnLiEbPLTKqE8AzoABO61dVky7ZIuvNzY6BjD6i9RXqbyz79hBpPEHX5Q
8P3DzmR99WQsTgIj2D3qLvYyshoqgXQlxzxp
-----END PRIVATE KEY-----`,
        pkixPublicKey: `-----BEGIN PUBLIC KEY-----
ME8wEQYIKyQDAwIFAgEGBSuBBAAhAzoABO61dVky7ZIuvNzY6BjD6i9RXqbyz79h
BpPEHX5Q8P3DzmR99WQsTgIj2D3qLvYyshoqgXQlxzxp
-----END PUBLIC KEY-----`,
        msg: `1111111111111111111111111111111122222222222222222222223333333333333333
`,
        sig: fromBase64("MD0CHDOpFd+Fa5dliqUE6pwqa2bN1MmsDDdEncSaRh4CHQCovf7MyLUg/xPTtIY45pscV2NHCgSoiVQ2e9F4"),
    },
    // botan keygen --algo=ECGDSA --params=secp256r1 | tee priv.pem; botan pkcs8 --pub-out priv.pem | tee pub.pem
    {
        pkcs8PrivateKey: `-----BEGIN PRIVATE KEY-----
MIGIAgEAMBQGCCskAwMCBQIBBggqhkjOPQMBBwRtMGsCAQEEIEOx0qpCDkE7a0iX
nFecDv2bC0ozzoQS8Ao+SjheegOEoUQDQgAELAxKd0QeboAKI5AKatycaAA7EYPH
SpyEA9FzZ4dTHLePEBfCkN+qKAa6jSw06PvxNOPgPnMs5iiotGepVE/JYg==
-----END PRIVATE KEY-----`,
        pkixPublicKey: `-----BEGIN PUBLIC KEY-----
MFowFAYIKyQDAwIFAgEGCCqGSM49AwEHA0IABCwMSndEHm6ACiOQCmrcnGgAOxGD
x0qchAPRc2eHUxy3jxAXwpDfqigGuo0sNOj78TTj4D5zLOYoqLRnqVRPyWI=
-----END PUBLIC KEY-----`,
        msg: `1111111111111111111111111111111122222222222222222222223333333333333333
`,
        sig: fromBase64("MEUCIQDS2RXiCqWHhOdua+fvaESF6N1mDBjBO8vv05Uxq1ZJsAIges9+59UTWRHWljwmsp2JlaUuD3KSZFo2SI3GCrrIJns="),
    },
    // botan keygen --algo=ECGDSA --params=secp384r1 | tee priv.pem; botan pkcs8 --pub-out priv.pem | tee pub.pem
    {
        pkcs8PrivateKey: `-----BEGIN PRIVATE KEY-----
MIG3AgEAMBEGCCskAwMCBQIBBgUrgQQAIgSBnjCBmwIBAQQwbZ6M6oeDCTh5e2lC
/rR3jVrZ7NkDyZinW3nG0gdm1rlee6piLNNuPIF3i7VQaK1XoWQDYgAEOzfgS1m2
VAc07wGNEeNuVfZpG7UiMBuF4gPuhde7a0sCWDvp/H8pQuFH1Jd1ijV8youexIAx
cfE25fu/QkqPgzkC1ocZVQfeTSW+NgotZDwzvYssmXUdjgc33WGcAKxt
-----END PRIVATE KEY-----`,
        pkixPublicKey: `-----BEGIN PUBLIC KEY-----
MHcwEQYIKyQDAwIFAgEGBSuBBAAiA2IABDs34EtZtlQHNO8BjRHjblX2aRu1IjAb
heID7oXXu2tLAlg76fx/KULhR9SXdYo1fMqLnsSAMXHxNuX7v0JKj4M5AtaHGVUH
3k0lvjYKLWQ8M72LLJl1HY4HN91hnACsbQ==
-----END PUBLIC KEY-----`,
        msg: `1111111111111111111111111111111122222222222222222222223333333333333333
`,
        sig: fromBase64("MGUCMQDSVRfqCmyXHO+A/TV+wCvFWRXTBfHl3XilUhtqn9bOWDvfPnk9+l2eykH4xC+ZgdwCMBvtq/jMkuXgJbK1ZEXTQAwlRJ2yHQnzI+hGGqYKSWboNDbp8RqzBP+cCUXb/ZvOBw=="),
    },
    // botan keygen --algo=ECGDSA --params=secp521r1 | tee priv.pem; botan pkcs8 --pub-out priv.pem | tee pub.pem
    {
        pkcs8PrivateKey: `-----BEGIN PRIVATE KEY-----
MIHvAgEAMBEGCCskAwMCBQIBBgUrgQQAIwSB1jCB0wIBAQRCAdsCfYyoYQxYm3jh
3WyN3zapCr1MsCX8ozFTq47kYgeb5U5zBB79B7Ra6iBQfG2V8CInloDsXi+p1n5a
yIV+Ab5hoYGJA4GGAAQB7QbJQ+GmBV2X0EzUBCShB8HehflvTUPbtJXo5D7bnCmd
heOzJneOONmHw87d/qxhDGSN17JycXStt586J4B7EBsAXq596806GsmsNE548Hzy
jzJOZe1rr5hZuw0pEdr/5U8XyDD4OD8xH0DL99O3TXBhHMWCJ7Dis/hU8zYEx101
WVI=
-----END PRIVATE KEY-----`,
        pkixPublicKey: `-----BEGIN PUBLIC KEY-----
MIGcMBEGCCskAwMCBQIBBgUrgQQAIwOBhgAEAe0GyUPhpgVdl9BM1AQkoQfB3oX5
b01D27SV6OQ+25wpnYXjsyZ3jjjZh8PO3f6sYQxkjdeycnF0rbefOieAexAbAF6u
fevNOhrJrDROePB88o8yTmXta6+YWbsNKRHa/+VPF8gw+Dg/MR9Ay/fTt01wYRzF
giew4rP4VPM2BMddNVlS
-----END PUBLIC KEY-----`,
        msg: `1111111111111111111111111111111122222222222222222222223333333333333333
`,
        sig: fromBase64("MIGIAkIBEzK2sNXoDe0URlqZs70Lv8yy3pRJUSARXopuq6+ve/ve4EcFxCcKk2o21vp/MBSCHghJfgKimDrUuG5Zn3AQyrYCQgGzfkYkbCwTDGtZGdsSh61x6yAWkXk2wpP8qC3o+w3tlFkPJjUp1iixKyUZvevnmqCB7TMed6bbO3gME+veaVOwzg=="),
    },
}

