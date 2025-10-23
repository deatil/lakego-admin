package kg

import (
    "testing"
    "crypto/rand"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/elliptic/kg"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func test_MarshalPKCS1(t *testing.T, curve elliptic.Curve) {
    private, err := GenerateKey(rand.Reader, curve)
    if err != nil {
        t.Fatal(err)
    }

    prikey, err := MarshalECPrivateKey(private)
    if err != nil {
        t.Errorf("MarshalECPrivateKey error: %s", err)
    }

    parsedPri, err := ParseECPrivateKey(prikey)
    if err != nil {
        t.Errorf("ParseECPrivateKey error: %s", err)
    }

    if !private.Equal(parsedPri) {
        t.Errorf("parsedPri error")
    }

    // t.Errorf("%s \n", encodePEM(prikey, "KG PRIVATE KEY"))
}

func Test_MarshalPKCS1(t *testing.T) {
    t.Run("KG256r1", func(t *testing.T) {
        test_MarshalPKCS1(t, kg.KG256r1())
    })
    t.Run("KG384r1", func(t *testing.T) {
        test_MarshalPKCS1(t, kg.KG384r1())
    })
}

func test_MarshalPKCS8(t *testing.T, curve elliptic.Curve) {
    private, err := GenerateKey(rand.Reader, curve)
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

    // t.Errorf("%s, %s \n", encodePEM(pubkey, "PUBLIC KEY"), encodePEM(prikey, "PRIVATE KEY"))
}

func Test_MarshalPKCS8(t *testing.T) {
    t.Run("KG256r1", func(t *testing.T) {
        test_MarshalPKCS8(t, kg.KG256r1())
    })
    t.Run("KG384r1", func(t *testing.T) {
        test_MarshalPKCS8(t, kg.KG384r1())
    })
}

var privPEM = `-----BEGIN PRIVATE KEY-----
MIGDAgEAMA8GBWBkAQEBBgZgZAEBAQEEbTBrAgEBBCBcE+nd3ewm44k3D0tYm1kN
Vcv0YYE0zMZAnXELpkN6+qFEA0IABMT+RpdcCBSxapp4/hDTLEBTj9GNmswO3bAT
Fvmu6WhHCCBI6keys6sxBOfrhwdD5aHfMlIwwI7I5D+VwMIB2nI=
-----END PRIVATE KEY-----
`

var pubPEM = `-----BEGIN PUBLIC KEY-----
MFUwDwYFYGQBAQEGBmBkAQEBAQNCAATE/kaXXAgUsWqaeP4Q0yxAU4/RjZrMDt2w
Exb5ruloRwggSOpHsrOrMQTn64cHQ+Wh3zJSMMCOyOQ/lcDCAdpy
-----END PUBLIC KEY-----
`

func Test_PKCS8_Check(t *testing.T) {
    test_PKCS8_Check(t, privPEM, pubPEM)
}

func test_PKCS8_Check(t *testing.T, priv, pub string) {
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

var privPKCS1PEM = `-----BEGIN KG PRIVATE KEY-----
MHUCAQEEIBMETMHisWFkMSTOv6I3MzDjVE2vGUmYV+BThO/Hn4C5oAgGBmBkAQEB
AaFEA0IABDEqAIvFad2d7KwMTQ2lEIKoI5b901l8odC6IkjwKaREp0eXcBz+zA53
jVs4KT+AcWEFlaWSK3rv0ikd+8M116E=
-----END KG PRIVATE KEY-----
`

func Test_PKCS1_Check(t *testing.T) {
    test_PKCS1_Check(t, privPKCS1PEM)
}

func test_PKCS1_Check(t *testing.T, priv string) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    parsedPriv, err := ParseECPrivateKey(decodePEM(priv))
    if err != nil {
        t.Errorf("ParseECPrivateKey error: %s", err)
    }

    privkey, err := MarshalECPrivateKey(parsedPriv)
    if err != nil {
        t.Errorf("MarshalECPrivateKey error: %s", err)
    }

    privPemCheck := encodePEM(privkey, "KG PRIVATE KEY")
    assertEqual(privPemCheck, priv, "test_Marshal_Check privkey")
}
