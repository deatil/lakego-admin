package ecdsa_test

import (
    "fmt"
    "testing"
    "crypto/rand"
    "crypto/ecdsa"
    "crypto/elliptic"
    "encoding/pem"
    "encoding/asn1"

    cryptobin_ecdsa "github.com/deatil/go-cryptobin/pubkey/ecdsa"
    cryptobin_koblitz "github.com/deatil/go-cryptobin/elliptic/koblitz"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var (
    // 测试 OID，非正确 OID
    oidPublicKeyP192k1Test = asn1.ObjectIdentifier{1, 9, 107, 123, 666}
)

func init() {
    cryptobin_ecdsa.AddNamedCurve(cryptobin_koblitz.P192k1(), oidPublicKeyP192k1Test)
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

func Test_PKCS8PrivateKey(t *testing.T) {
    test_PKCS8PrivateKey(t, elliptic.P224())
    test_PKCS8PrivateKey(t, elliptic.P256())
    test_PKCS8PrivateKey(t, elliptic.P384())
    test_PKCS8PrivateKey(t, elliptic.P521())

    test_PKCS8PrivateKey(t, cryptobin_koblitz.P192k1())
}

func test_PKCS8PrivateKey(t *testing.T, curue elliptic.Curve) {
    t.Run(fmt.Sprintf("%s", curue), func(t *testing.T) {
        priv, err := ecdsa.GenerateKey(curue, rand.Reader)
        if err != nil {
            t.Fatal(err)
        }

        pub := priv.Public().(*ecdsa.PublicKey)

        pubDer, err := cryptobin_ecdsa.MarshalPublicKey(pub)
        if err != nil {
            t.Fatal(err)
        }
        privDer, err := cryptobin_ecdsa.MarshalPrivateKey(priv)
        if err != nil {
            t.Fatal(err)
        }

        if len(privDer) == 0 {
            t.Error("expected export key Der error: priv")
        }
        if len(pubDer) == 0 {
            t.Error("expected export key Der error: pub")
        }

        newPub, err := cryptobin_ecdsa.ParsePublicKey(pubDer)
        if err != nil {
            t.Fatal(err)
        }
        newPriv, err := cryptobin_ecdsa.ParsePrivateKey(privDer)
        if err != nil {
            t.Fatal(err)
        }

        if !newPriv.Equal(priv) {
            t.Error("Marshal privekey error")
        }
        if !newPub.Equal(pub) {
            t.Error("Marshal public error")
        }
    })
}

func Test_PKCS1PrivateKey(t *testing.T) {
    test_PKCS1PrivateKey(t, elliptic.P224())
    test_PKCS1PrivateKey(t, elliptic.P256())
    test_PKCS1PrivateKey(t, elliptic.P384())
    test_PKCS1PrivateKey(t, elliptic.P521())

    test_PKCS1PrivateKey(t, cryptobin_koblitz.P192k1())
}

func test_PKCS1PrivateKey(t *testing.T, curue elliptic.Curve) {
    t.Run(fmt.Sprintf("%s", curue), func(t *testing.T) {
        priv, err := ecdsa.GenerateKey(curue, rand.Reader)
        if err != nil {
            t.Fatal(err)
        }

        privDer, err := cryptobin_ecdsa.MarshalECPrivateKey(priv)
        if err != nil {
            t.Fatal(err)
        }

        if len(privDer) == 0 {
            t.Error("expected export key Der error: EC priv")
        }

        newPriv, err := cryptobin_ecdsa.ParseECPrivateKey(privDer)
        if err != nil {
            t.Fatal(err)
        }

        if !newPriv.Equal(priv) {
            t.Error("Marshal EC privekey error")
        }
    })
}

var testPkcs1Prikey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJZUd8PUuNjOIjhTfX6hn/FAGbfReYbxH/DG5dXQhbB0oAoGCCqGSM49
AwEHoUQDQgAEebQAt4xsY2LYkgWR+r6jFjLtTI61p4ah7X7fQ/SRhB3CdF75kU6b
XWJo3P4DOLMiK3WiF625es36MUYbzUDj7g==
-----END EC PRIVATE KEY-----
`
var testPkcs8Prikey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgllR3w9S42M4iOFN9
fqGf8UAZt9F5hvEf8Mbl1dCFsHShRANCAAR5tAC3jGxjYtiSBZH6vqMWMu1MjrWn
hqHtft9D9JGEHcJ0XvmRTptdYmjc/gM4syIrdaIXrbl6zfoxRhvNQOPu
-----END PRIVATE KEY-----
`

func Test_PKCS1PrivateKeyCheck(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    pri := decodePEM(testPkcs1Prikey)

    priv, err := cryptobin_ecdsa.ParseECPrivateKey(pri)
    if err != nil {
        t.Fatal(err)
    }

    assertNoError(err, "PKCS1PrivateKeyCheck")
    assertNotEmpty(priv, "PKCS1PrivateKeyCheck")

    privDer, err := cryptobin_ecdsa.MarshalECPrivateKey(priv)
    if err != nil {
        t.Fatal(err)
    }

    newPriv := encodePEM(privDer, "EC PRIVATE KEY")

    assertEqual(newPriv, testPkcs1Prikey, "PKCS1PrivateKeyCheck")
}

func Test_PKCS8PrivateKeyCheck(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    pri := decodePEM(testPkcs8Prikey)

    priv, err := cryptobin_ecdsa.ParsePrivateKey(pri)
    if err != nil {
        t.Fatal(err)
    }

    assertNoError(err, "PKCS8PrivateKeyCheck")
    assertNotEmpty(priv, "PKCS8PrivateKeyCheck")

    privDer, err := cryptobin_ecdsa.MarshalPrivateKey(priv)
    if err != nil {
        t.Fatal(err)
    }

    assertNotEmpty(privDer, "PKCS8PrivateKeyCheck")
}
