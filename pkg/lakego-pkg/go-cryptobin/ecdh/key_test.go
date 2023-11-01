package ecdh_test

import (
    "fmt"
    "bytes"
    "testing"
    "crypto/rand"
    "encoding/pem"

    "github.com/tjfoc/gmsm/sm2"
    "github.com/tjfoc/gmsm/x509"

    "github.com/deatil/go-cryptobin/ecdh"
)

func TestEqual(t *testing.T) {
    testOneCurve(t, ecdh.P256())
    testOneCurve(t, ecdh.P384())
    testOneCurve(t, ecdh.P521())
    testOneCurve(t, ecdh.X25519())
    testOneCurve(t, ecdh.X448())

    testOneCurve(t, ecdh.GmSM2())
}

func testOneCurve(t *testing.T, curue ecdh.Curve) {
    t.Run(fmt.Sprintf("%s", curue), func(t *testing.T) {
        priv, err := curue.GenerateKey(rand.Reader)
        if err != nil {
            t.Fatal(err)
        }

        pub := priv.PublicKey()

        pubDer, err := ecdh.MarshalPublicKey(pub)
        if err != nil {
            t.Fatal(err)
        }
        privDer, err := ecdh.MarshalPrivateKey(priv)
        if err != nil {
            t.Fatal(err)
        }

        if len(privDer) == 0 {
            t.Error("expected export key Der error: priv")
        }
        if len(pubDer) == 0 {
            t.Error("expected export key Der error: pub")
        }

        newPub, err := ecdh.ParsePublicKey(pubDer)
        if err != nil {
            t.Fatal(err)
        }
        newPriv, err := ecdh.ParsePrivateKey(privDer)
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

var (
    // 本地密钥
    testSM2Prikey = `
-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgqTmwkRE7Z8UaUxP/
in7PM0Cs+HPdiEN2S/ryXCLKW3OgCgYIKoEcz1UBgi2hRANCAATVHOEvbcIk9HbO
/+VGIEuvzZB5Vk1nLinD4MslJRZIC/guCwBAHxUPQO2xMMtxqXV59f5DKGl3YAvD
uoEhTEHN
-----END PRIVATE KEY-----
    `
    testSM2Pubkey = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE1RzhL23CJPR2zv/lRiBLr82QeVZN
Zy4pw+DLJSUWSAv4LgsAQB8VD0DtsTDLcal1efX+Qyhpd2ALw7qBIUxBzQ==
-----END PUBLIC KEY-----
    `

    // 对方密钥
    testSM2Prikey2 = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgBh/5ZbHdkwXhwteN
OYecASnP778U0BLZ4suYZf5XvIOhRANCAASQ2AGZRgNjUwkiujPI24Abec5HM1MK
ghJ+FA8z/WrZyNjgBKEV1Fm7SiVfoIuaKIGHPFm1vbkKNCqpPijXWPcM
-----END PRIVATE KEY-----
    `
    testSM2Pubkey2 = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEkNgBmUYDY1MJIrozyNuAG3nORzNT
CoISfhQPM/1q2cjY4AShFdRZu0olX6CLmiiBhzxZtb25CjQqqT4o11j3DA==
-----END PUBLIC KEY-----
    `
)

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

func test_MakeKeys(t *testing.T) {
    pri, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub := &pri.PublicKey

    privateDer, _ := x509.MarshalSm2UnecryptedPrivateKey(pri)
    pubkeyDer, _ := x509.MarshalSm2PublicKey(pub)

    t.Error(encodePEM(privateDer, "PRIVATE KEY"))
    t.Error(encodePEM(pubkeyDer, "PUBLIC KEY"))
}

// 对称密钥检测
func Test_MakeECDHKey(t *testing.T) {
    key1 := test_MakeECDHKey(t, testSM2Prikey, testSM2Pubkey2)
    if len(key1) == 0 {
        t.Error("make key1 error")
    }

    key2 := test_MakeECDHKey(t, testSM2Prikey2, testSM2Pubkey)
    if len(key2) == 0 {
        t.Error("make key2 error")
    }

    if !bytes.Equal(key1, key2) {
        t.Errorf("want %x, got %x", key1, key2)
    }
}

// 生成 ecdh 密钥
func test_MakeECDHKey(t *testing.T, pril string, publ string) []byte {
    pri, err := x509.ReadPrivateKeyFromPem([]byte(pril), nil)
    if err != nil {
        t.Fatal(err)
    }

    pub, err := x509.ReadPublicKeyFromPem([]byte(publ))
    if err != nil {
        t.Fatal(err)
    }

    ecdhPub, err := ecdh.SM2PublicKeyToECDH(pub)
    if err != nil {
        t.Fatal(err)
    }

    ecdhPriv, err := ecdh.SM2PrivateKeyToECDH(pri)
    if err != nil {
        t.Fatal(err)
    }

    newkey, err := ecdhPriv.ECDH(ecdhPub)
    if err != nil {
        t.Fatal(err)
    }

    return newkey
}
