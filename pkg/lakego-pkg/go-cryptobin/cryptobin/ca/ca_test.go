package ca

import (
    "net"
    "errors"
    "testing"
    "encoding/pem"
    "crypto/dsa"
    "crypto/rsa"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/pubkey/gost"
    cryptobin_x509 "github.com/deatil/go-cryptobin/x509"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_To(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    testssh := New()
    testssh.keyData = []byte("test")

    assertEqual(testssh.ToKeyBytes(), []byte("test"), "Test_OnError Error")
    assertEqual(testssh.ToKeyString(), "test", "Test_OnError Error")
}

func Test_OnError(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    err := errors.New("test-error")

    testssh := New()
    testssh.Errors = append(testssh.Errors, err)

    testssh = testssh.OnError(func(errs []error) {
        assertEqual(errs, []error{err}, "Test_OnError")
    })

    err2 := testssh.Error().Error()
    assertEqual(err2, err.Error(), "Test_OnError Error")
}

func Test_CreateCA(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := New().
        SetPublicKeyType("RSA").
        WithBits(512).
        GenerateKey().
        MakeCA(pkix.Name{
            CommonName:   "test.example.com",
            Organization: []string{"Test Organization"},
        }, 2, "SHA256WithRSA")

    ca := obj.CreateCA().ToKeyString()
    prikey := obj.CreatePrivateKey().ToKeyString()

    assertNoError(obj.Error(), "Test_CreateCA")
    assertNotEmpty(ca, "Test_CreateCA-ca")
    assertNotEmpty(prikey, "Test_CreateCA-prikey")

    // ===========

    // Parse Certificate PEM
    parsePubkey := New().
        FromCertificate([]byte(ca)).
        GetPublicKey()

    assertEqual(parsePubkey, obj.GetPublicKey(), "Test_CreateCA")

    // ===========

    block, _ := pem.Decode([]byte(ca))
    if block == nil {
        t.Fatal("failed to read cert")
    }

    cert, err := cryptobin_x509.ParseCertificate(block.Bytes)
    if err != nil {
        t.Fatal("failed to read cert file")
    }

    err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
    if err != nil {
        t.Fatal(err)
    }
}

func Test_CreateCAWithIssuer(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := New().
        SetPublicKeyType("RSA").
        WithBits(512).
        GenerateKey().
        MakeCA(pkix.Name{
            CommonName:   "test.example.com",
            Organization: []string{"Test Organization"},
        }, 2, "SHA256WithRSA")

    root := obj.CreateCA().ToKeyString()
    prikey := obj.CreatePrivateKey().ToKeyString()

    assertNoError(obj.Error(), "Test_CreateCAWithIssuer")
    assertNotEmpty(root, "Test_CreateCAWithIssuer-root")
    assertNotEmpty(prikey, "Test_CreateCAWithIssuer-prikey")

    // ===========

    obj2 := New().
        SetPublicKeyType("RSA").
        WithBits(512).
        GenerateKey().
        MakeCA(pkix.Name{
            CommonName:   "test22.example.com",
            Organization: []string{"Test22 Organization"},
        }, 3, "SHA256WithRSA").
        CreateCAWithIssuer(obj.GetCert(), obj.GetPrivateKey())
    ca := obj2.ToKeyString()

    assertNoError(obj2.Error(), "Test_CreateCAWithIssuer-CreateCert")
    assertNotEmpty(ca, "Test_CreateCAWithIssuer-CreateCert")

    // ===========

    // Parse Certificate PEM
    parsePubkey := New().
        FromCertificate([]byte(ca)).
        GetPublicKey()

    assertEqual(parsePubkey, obj2.GetPublicKey(), "Test_CreateCAWithIssuer")
}

func Test_CreateCert(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := New().
        SetPublicKeyType("RSA").
        WithBits(512).
        GenerateKey().
        MakeCA(pkix.Name{
            CommonName:   "test.example.com",
            Organization: []string{"Test Organization"},
        }, 2, "SHA256WithRSA")

    ca := obj.CreateCA().ToKeyString()
    prikey := obj.CreatePrivateKey().ToKeyString()

    assertNoError(obj.Error(), "Test_CreateCert")
    assertNotEmpty(ca, "Test_CreateCert")
    assertNotEmpty(prikey, "Test_CreateCert-prikey")

    // ===========

    obj2 := New().
        SetPublicKeyType("RSA").
        WithBits(512).
        GenerateKey().
        MakeCert(pkix.Name{
            CommonName:   "test.example.com",
            Organization: []string{"Test Organization"},
            Country:      []string{"China"},
        }, 2, []string{
            "test.example.com",
        }, []net.IP{
            net.IPv4(127, 0, 0, 1).To4(),
            net.ParseIP("2001:4860:0:2001::68"),
        }, "SHA256WithRSA").
        CreateCert(obj.GetCert(), obj.GetPrivateKey())
    cert := obj2.ToKeyString()

    assertNoError(obj2.Error(), "Test_CreateCert-CreateCert")
    assertNotEmpty(cert, "Test_CreateCert-CreateCert")

    // ===========

    // Parse Certificate PEM
    parsePubkey := New().
        FromCertificate([]byte(cert)).
        GetPublicKey()

    assertEqual(parsePubkey, obj2.GetPublicKey(), "Test_CreateCert")
}

func Test_CreateCSR(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := New().
        SetPublicKeyType("RSA").
        WithBits(512).
        GenerateKey().
        MakeCSR(
            "test.example.com",
            []string{"Test"},
            "SHA256WithRSA",
        )

    cert0 := obj.CreateCSR().ToKeyString()
    prikey := obj.CreatePrivateKey().ToKeyString()

    assertNoError(obj.Error(), "Test_CreateCSR")
    assertNotEmpty(cert0, "Test_CreateCSR")
    assertNotEmpty(prikey, "Test_CreateCSR-prikey")

    // ===========

    // Parse Certificate PEM
    parsePubkey := New().
        FromCertificateRequest([]byte(cert0)).
        GetPublicKey()

    assertEqual(parsePubkey, obj.GetPublicKey(), "Test_CreateCSR")

    // ===========

    block, _ := pem.Decode([]byte(cert0))
    if block == nil {
        t.Fatal("failed to read cert")
    }

    cert, err := cryptobin_x509.ParseCertificateRequest(block.Bytes)
    if err != nil {
        t.Fatal("failed to read cert file")
    }

    err = cert.CheckSignature()
    if err != nil {
        t.Fatal(err)
    }
}

func Test_UpdateCert(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    obj := New().
        MakeCA(pkix.Name{
            CommonName:   "test.example.com",
            Organization: []string{"Test Organization"},
        }, 2, "SHA256WithRSA").
        UpdateCert(func(cert *cryptobin_x509.Certificate) {
            cert.SubjectKeyId = []byte{1, 2, 3, 4, 6, 7}
        }).
        GetCert()

    assertEqual(obj.SubjectKeyId, []byte{1, 2, 3, 4, 6, 7}, "Test_UpdateCert")
}

func Test_UpdateCertRequest(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    obj := New().
        MakeCSR(
            "test.example.com",
            []string{"Test"},
            "SHA256WithRSA",
        ).
        UpdateCertRequest(func(cert *cryptobin_x509.CertificateRequest) {
            cert.Subject.CommonName = "test11.example.com"
        }).
        GetCertRequest()

    assertEqual(obj.Subject.CommonName, "test11.example.com", "Test_UpdateCertRequest")
}

func Test_GenerateKey(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    t.Run("GenerateRSAKey", func(t *testing.T) {
        obj := New().
            SetPublicKeyType("RSA").
            WithBits(2048).
            GenerateKey()

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertNoError(obj.Error(), "Test_GenerateKey")
        assertNotEmpty(prikey, "Test_GenerateKey-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey-pubkey")

        pass := []byte("12345678")
        prikey2 := obj.CreatePrivateKeyWithPassword(pass).ToKeyString()

        assertNotEmpty(prikey2, "Test_GenerateKey-prikey2")

        prikey22 := New().
            FromPrivateKey([]byte(prikey)).
            GetPrivateKey()
        assertEqual(prikey22, obj.GetPrivateKey(), "Test_GenerateKey-FromPrivateKey")

        prikey223 := New().
            FromPrivateKeyWithPassword([]byte(prikey2), pass).
            GetPrivateKey()
        assertEqual(prikey223, obj.GetPrivateKey(), "Test_GenerateKey-FromPrivateKeyWithPassword")

        pubkey22 := New().
            FromPublicKey([]byte(pubkey)).
            GetPublicKey()
        assertEqual(pubkey22, obj.GetPublicKey(), "Test_GenerateKey-FromPublicKey")

    })

    t.Run("GenerateDSAKey", func(t *testing.T) {
        obj := New().
            SetPublicKeyType("DSA").
            SetParameterSizes("L1024N160").
            GenerateKey()

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertNoError(obj.Error(), "Test_GenerateKey")
        assertNotEmpty(prikey, "Test_GenerateKey-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey-pubkey")

        pass := []byte("12345678")
        prikey2 := obj.CreatePrivateKeyWithPassword(pass).ToKeyString()

        assertNotEmpty(prikey2, "Test_GenerateKey-prikey2")

        prikey22 := New().
            FromPrivateKey([]byte(prikey)).
            GetPrivateKey()
        assertEqual(prikey22, obj.GetPrivateKey(), "Test_GenerateKey-FromPrivateKey")

        prikey223 := New().
            FromPrivateKeyWithPassword([]byte(prikey2), pass).
            GetPrivateKey()
        assertEqual(prikey223, obj.GetPrivateKey(), "Test_GenerateKey-FromPrivateKeyWithPassword")

        pubkey22 := New().
            FromPublicKey([]byte(pubkey)).
            GetPublicKey()
        assertEqual(pubkey22, obj.GetPublicKey(), "Test_GenerateKey-FromPublicKey")
    })

    t.Run("GenerateECDSAKey", func(t *testing.T) {
        obj := New().
            SetPublicKeyType("ECDSA").
            SetCurve("P256").
            GenerateKey()

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertNoError(obj.Error(), "Test_GenerateKey")
        assertNotEmpty(prikey, "Test_GenerateKey-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey-pubkey")

        pass := []byte("12345678")
        prikey2 := obj.CreatePrivateKeyWithPassword(pass).ToKeyString()

        assertNotEmpty(prikey2, "Test_GenerateKey-prikey2")

        prikey22 := New().
            FromPrivateKey([]byte(prikey)).
            GetPrivateKey()
        assertEqual(prikey22, obj.GetPrivateKey(), "Test_GenerateKey-FromPrivateKey")

        prikey223 := New().
            FromPrivateKeyWithPassword([]byte(prikey2), pass).
            GetPrivateKey()
        assertEqual(prikey223, obj.GetPrivateKey(), "Test_GenerateKey-FromPrivateKeyWithPassword")

        pubkey22 := New().
            FromPublicKey([]byte(pubkey)).
            GetPublicKey()
        assertEqual(pubkey22, obj.GetPublicKey(), "Test_GenerateKey-FromPublicKey")
    })

    t.Run("GenerateEdDSAKey", func(t *testing.T) {
        obj := New().
            SetPublicKeyType("EdDSA").
            GenerateKey()

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertNoError(obj.Error(), "Test_GenerateKey")
        assertNotEmpty(prikey, "Test_GenerateKey-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey-pubkey")

        pass := []byte("12345678")
        prikey2 := obj.CreatePrivateKeyWithPassword(pass).ToKeyString()

        assertNotEmpty(prikey2, "Test_GenerateKey-prikey2")

        prikey22 := New().
            FromPrivateKey([]byte(prikey)).
            GetPrivateKey()
        assertEqual(prikey22, obj.GetPrivateKey(), "Test_GenerateKey-FromPrivateKey")

        prikey223 := New().
            FromPrivateKeyWithPassword([]byte(prikey2), pass).
            GetPrivateKey()
        assertEqual(prikey223, obj.GetPrivateKey(), "Test_GenerateKey-FromPrivateKeyWithPassword")

        pubkey22 := New().
            FromPublicKey([]byte(pubkey)).
            GetPublicKey()
        assertEqual(pubkey22, obj.GetPublicKey(), "Test_GenerateKey-FromPublicKey")
    })

    t.Run("GenerateSM2Key", func(t *testing.T) {
        obj := New().
            SetPublicKeyType("SM2").
            GenerateKey()

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertNoError(obj.Error(), "Test_GenerateKey")
        assertNotEmpty(prikey, "Test_GenerateKey-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey-pubkey")

        pass := []byte("12345678")
        prikey2 := obj.CreatePrivateKeyWithPassword(pass).ToKeyString()

        assertNotEmpty(prikey2, "Test_GenerateKey-prikey2")

        prikey22 := New().
            FromPrivateKey([]byte(prikey)).
            GetPrivateKey()
        assertEqual(prikey22, obj.GetPrivateKey(), "Test_GenerateKey-FromPrivateKey")

        prikey223 := New().
            FromPrivateKeyWithPassword([]byte(prikey2), pass).
            GetPrivateKey()
        assertEqual(prikey223, obj.GetPrivateKey(), "Test_GenerateKey-FromPrivateKeyWithPassword")

        pubkey22 := New().
            FromPublicKey([]byte(pubkey)).
            GetPublicKey()
        assertEqual(pubkey22, obj.GetPublicKey(), "Test_GenerateKey-FromPublicKey")
    })

    t.Run("GenerateGostKey", func(t *testing.T) {
        obj := New().
            SetPublicKeyType("Gost").
            SetGostCurve("IdGostR34102001CryptoProAParamSet").
            GenerateKey()

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertNoError(obj.Error(), "Test_GenerateKey")
        assertNotEmpty(prikey, "Test_GenerateKey-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey-pubkey")

        pass := []byte("12345678")
        prikey2 := obj.CreatePrivateKeyWithPassword(pass).ToKeyString()

        assertNotEmpty(prikey2, "Test_GenerateKey-prikey2")

        prikey22 := New().
            FromPrivateKey([]byte(prikey)).
            GetPrivateKey()
        assertEqual(prikey22, obj.GetPrivateKey(), "Test_GenerateKey-FromPrivateKey")

        prikey223 := New().
            FromPrivateKeyWithPassword([]byte(prikey2), pass).
            GetPrivateKey()
        assertEqual(prikey223, obj.GetPrivateKey(), "Test_GenerateKey-FromPrivateKeyWithPassword")

        pubkey22 := New().
            FromPublicKey([]byte(pubkey)).
            GetPublicKey()
        assertEqual(pubkey22, obj.GetPublicKey(), "Test_GenerateKey-FromPublicKey")
    })

    t.Run("GenerateElGamalKey", func(t *testing.T) {
        obj := New().
            SetPublicKeyType("ElGamal").
            WithBitsize(256).
            WithProbability(64).
            GenerateKey()

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertNoError(obj.Error(), "Test_GenerateKey")
        assertNotEmpty(prikey, "Test_GenerateKey-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey-pubkey")

        pass := []byte("12345678")
        prikey2 := obj.CreatePrivateKeyWithPassword(pass).ToKeyString()

        assertNotEmpty(prikey2, "Test_GenerateKey-prikey2")

        prikey22 := New().
            FromPrivateKey([]byte(prikey))

        assertEqual(prikey22.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenerateKey-FromPrivateKey")
        assertEqual(prikey22.GetPrivateKeyType().String(), "ElGamal", "Test_GenerateKey-GetPrivateKeyType")

        prikey223 := New().
            FromPrivateKeyWithPassword([]byte(prikey2), pass)

        assertEqual(prikey223.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenerateKey-FromPrivateKeyWithPassword")
        assertEqual(prikey223.GetPrivateKeyType().String(), "ElGamal", "Test_GenerateKey-GetPrivateKeyType")

        pubkey22 := New().
            FromPublicKey([]byte(pubkey))

        assertEqual(pubkey22.GetPublicKey(), obj.GetPublicKey(), "Test_GenerateKey-FromPublicKey")
        assertEqual(pubkey22.GetPublicKeyType().String(), "ElGamal", "Test_GenerateKey-GetPublicKeyType")
    })

    t.Run("GenerateRSAKey 2", func(t *testing.T) {
        obj := New().
            SetGenerateType("RSA").
            WithBits(2048).
            GenerateKey()

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertNoError(obj.Error(), "Test_GenerateKey")
        assertNotEmpty(prikey, "Test_GenerateKey-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey-pubkey")

        pass := []byte("12345678")
        prikey2 := obj.CreatePrivateKeyWithPassword(pass).ToKeyString()

        assertNotEmpty(prikey2, "Test_GenerateKey-prikey2")

        prikey22 := New().
            FromPrivateKey([]byte(prikey)).
            GetPrivateKey()
        assertEqual(prikey22, obj.GetPrivateKey(), "Test_GenerateKey-FromPrivateKey")

        prikey223 := New().
            FromPrivateKeyWithPassword([]byte(prikey2), pass).
            GetPrivateKey()
        assertEqual(prikey223, obj.GetPrivateKey(), "Test_GenerateKey-FromPrivateKeyWithPassword")

        pubkey22 := New().
            FromPublicKey([]byte(pubkey)).
            GetPublicKey()
        assertEqual(pubkey22, obj.GetPublicKey(), "Test_GenerateKey-FromPublicKey")
    })

}

func Test_GenerateKey2(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    t.Run("GenerateRSAKey", func(t *testing.T) {
        obj := New().
            GenerateRSAKey(2048)

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertNoError(obj.Error(), "Test_GenerateKey2")
        assertNotEmpty(prikey, "Test_GenerateKey2-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey2-pubkey")
    })

    t.Run("GenerateDSAKey", func(t *testing.T) {
        obj := New().GenerateDSAKey("L2048N224")

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertNoError(obj.Error(), "Test_GenerateKey2")
        assertNotEmpty(prikey, "Test_GenerateKey2-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey2-pubkey")
    })

    t.Run("GenerateECDSAKey", func(t *testing.T) {
        obj := New().
            GenerateECDSAKey("P256")

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertNoError(obj.Error(), "Test_GenerateKey2")
        assertNotEmpty(prikey, "Test_GenerateKey2-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey2-pubkey")
    })

    t.Run("GenerateEdDSAKey", func(t *testing.T) {
        obj := New().
            GenerateEdDSAKey()

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertNoError(obj.Error(), "Test_GenerateKey2")
        assertNotEmpty(prikey, "Test_GenerateKey2-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey2-pubkey")
    })

    t.Run("GenerateSM2Key", func(t *testing.T) {
        obj := New().
            GenerateSM2Key()

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertNoError(obj.Error(), "Test_GenerateKey2")
        assertNotEmpty(prikey, "Test_GenerateKey2-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey2-pubkey")
    })

    t.Run("GenerateGostKey", func(t *testing.T) {
        obj := New().
            GenerateGostKey("Idtc26gost34102012256paramSetB")

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertNoError(obj.Error(), "Test_GenerateKey2")
        assertNotEmpty(prikey, "Test_GenerateKey2-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey2-pubkey")
    })

    t.Run("GenerateElGamalKey", func(t *testing.T) {
        obj := New().
            GenerateElGamalKey(256, 64)

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertNoError(obj.Error(), "Test_GenerateKey2")
        assertNotEmpty(prikey, "Test_GenerateKey2-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey2-pubkey")
    })

}

var prikey = `
-----BEGIN PRIVATE KEY-----
MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAshKL2U6CuLgNBmNs
SQNDrXbSbRNT8ZoyIEmijQ2mlkfxKbW8l5D83m41x+6Ml69t2hgJnHkg9rFHgf33
gyxlZwIDAQABAkA8IJkKIkFvf+4d9xpMOQb0HogE/p68mLVOQ67YdACJA2dSrWt6
BRuMS/09YgTnACqCg+iazLEyuPbPjUO1vijRAiEAyWEzF4as13nXSVkB//EWfTTx
gZHvdDeRq6VVWqPHpxkCIQDiXwIg0i7ZXCBxrOHPflaQwdvX9b7m0Ng2mL0qwrSA
fwIhAIWj/6gJNAL7VKfUbcNQV0BYNj1qf6J8jit+2RoBvqlhAiEAqBRtSxtk58VM
3brFC8C928vlRWvVbCKDd75fLuHVDlcCIQCNnCqes/3rG/wW7XTSNUWWYV5vTasb
I8MfrrxWD1Rkiw==
-----END PRIVATE KEY-----
`

var ca = `
-----BEGIN CERTIFICATE-----
MIIBpDCCAU6gAwIBAgIEWrCvfjANBgkqhkiG9w0BAQsFADA3MRowGAYDVQQKExFU
ZXN0IE9yZ2FuaXphdGlvbjEZMBcGA1UEAxMQdGVzdC5leGFtcGxlLmNvbTAeFw0y
NTAxMjEwMzAyNDFaFw0yNzAxMjEwMzAyNDFaMDcxGjAYBgNVBAoTEVRlc3QgT3Jn
YW5pemF0aW9uMRkwFwYDVQQDExB0ZXN0LmV4YW1wbGUuY29tMFwwDQYJKoZIhvcN
AQEBBQADSwAwSAJBAMhnlBxqreifypPjXmyqKZJxTcB5zIMC+OyNRIJc4/WdEBUB
1wmkyOC1Xvr+zuQ8ZaZXMw6n8iS6vP1jnoQnqhcCAwEAAaNCMEAwDgYDVR0PAQH/
BAQDAgKEMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAPBgNVHRMBAf8E
BTADAQH/MA0GCSqGSIb3DQEBCwUAA0EAVouJ/As5AYB2xXLq+JofSHWHxTAzvDUb
X9uwNjylgcpxpQUxMPAbSA5kBm6xZpUf2BJfAU76OEUtGA553HLb+g==
-----END CERTIFICATE-----
`

var cert = `
-----BEGIN CERTIFICATE-----
MIIB6DCCAZKgAwIBAgIEX2zomzANBgkqhkiG9w0BAQsFADA3MRowGAYDVQQKExFU
ZXN0IE9yZ2FuaXphdGlvbjEZMBcGA1UEAxMQdGVzdC5leGFtcGxlLmNvbTAeFw0y
NTAxMjEwMzAxMjdaFw0yNzAxMjEwMzAxMjdaMEcxDjAMBgNVBAYTBUNoaW5hMRow
GAYDVQQKExFUZXN0IE9yZ2FuaXphdGlvbjEZMBcGA1UEAxMQdGVzdC5leGFtcGxl
LmNvbTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDKDo13pjRkv+Kl86siezAjvJ5G
WoS5+G+8EQN/tEHdVFwSR1HqiOCZssRSUUvc0kcabfzPyP2L+BI4wiuQw9avAgMB
AAGjdjB0MA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYB
BQUHAwEwDgYDVR0OBAcEBQECAwQGMDMGA1UdEQQsMCqCEHRlc3QuZXhhbXBsZS5j
b22HBH8AAAGHECABSGAAACABAAAAAAAAAGgwDQYJKoZIhvcNAQELBQADQQBQl8Xq
pEW8DflR+wXtOXU7Q2KVLUrT4C7yaVwS7eMNsbEJerQxuUol6cTCjrILjtKsUjXT
LzsfMZ9rwrvY+PV+
-----END CERTIFICATE-----
`

var csrCert = `
-----BEGIN CERTIFICATE REQUEST-----
MIHkMIGPAgEAMCoxDTALBgNVBAoTBFRlc3QxGTAXBgNVBAMTEHRlc3QuZXhhbXBs
ZS5jb20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEAxzaL40xmGsagoNuG+ngJyVbh
Geoz6gRkXXBs5XyR8ENl9YybbLburu0ajR/vmh/XETTLG2DSBvows2FO1nl9fwID
AQABoAAwDQYJKoZIhvcNAQELBQADQQDE1jMQnEgNp3vg/Xj4YbXCtPOED3fGhyc0
JPuxgonqBqrDgFL6n1VnWxe8tz6gB3rCccGbNxdkWGzR9y3JQOFc
-----END CERTIFICATE REQUEST-----
`

func Test_CreatePKCS12Cert(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    pwd := "123123"

    obj := New().
        FromPrivateKey([]byte(prikey)).
        FromCertificate([]byte(cert)).
        CreatePKCS12Cert(nil, pwd)
    p12 := obj.ToKeyString()

    assertNoError(obj.Error(), "Test_CreatePKCS12Cert")
    assertNotEmpty(p12, "Test_CreatePKCS12Cert")

    // ===========

    parseP12 := New().FromPKCS12Cert([]byte(p12), pwd)

    assertEqual(parseP12.GetPrivateKey(), obj.GetPrivateKey(), "Test_CreatePKCS12Cert")
}

func Test_CreatePKCS12Cert2(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    ca0 := New().FromCertificate([]byte(ca))

    pwd := "123123"

    obj := New().
        FromPrivateKey([]byte(prikey)).
        FromCertificate([]byte(cert)).
        CreatePKCS12Cert([]*x509.Certificate{
            ca0.GetCert().ToX509Certificate(),
        }, pwd)
    p12 := obj.ToKeyString()

    assertNoError(obj.Error(), "Test_CreatePKCS12Cert2")
    assertNotEmpty(p12, "Test_CreatePKCS12Cert2")

    // ===========

    parseP12 := New().FromPKCS12Cert([]byte(p12), pwd)

    assertNoError(parseP12.Error(), "Test_CreatePKCS12Cert2-FromPKCS12Cert")
    assertEqual(parseP12.GetPrivateKey(), obj.GetPrivateKey(), "Test_CreatePKCS12Cert-FromPKCS12Cert")
}

var caRoot2 = `
-----BEGIN CERTIFICATE-----
MIIBpDCCAU6gAwIBAgIEDkDUsTANBgkqhkiG9w0BAQsFADA3MRowGAYDVQQKExFU
ZXN0IE9yZ2FuaXphdGlvbjEZMBcGA1UEAxMQdGVzdC5leGFtcGxlLmNvbTAeFw0y
NTAxMjEwNDU5NDhaFw0yNzAxMjEwNDU5NDhaMDcxGjAYBgNVBAoTEVRlc3QgT3Jn
YW5pemF0aW9uMRkwFwYDVQQDExB0ZXN0LmV4YW1wbGUuY29tMFwwDQYJKoZIhvcN
AQEBBQADSwAwSAJBAL3I4OGdootHGfvDwFpDxpMZvVPlLmuh/7gZWBtbn+bsjJgE
iY7GUEU044n/PFxHTAyPKEWGaUn/YbTcHdWJPTMCAwEAAaNCMEAwDgYDVR0PAQH/
BAQDAgKEMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAPBgNVHRMBAf8E
BTADAQH/MA0GCSqGSIb3DQEBCwUAA0EApskWhn6L3CEUDXZIMYt4fwoLLztsQzc3
5dP4kUkdEkRFzlO2BLqsEGpI+ADc08tPmjv3cstbMr5ktg3z73AgCQ==
-----END CERTIFICATE-----
`

var ca2 = `
-----BEGIN CERTIFICATE-----
MIIBqDCCAVKgAwIBAgIEQjmW/DANBgkqhkiG9w0BAQsFADA3MRowGAYDVQQKExFU
ZXN0IE9yZ2FuaXphdGlvbjEZMBcGA1UEAxMQdGVzdC5leGFtcGxlLmNvbTAeFw0y
NTAxMjEwNDU5NDhaFw0yODAxMjEwNDU5NDhaMDsxHDAaBgNVBAoTE1Rlc3QyMiBP
cmdhbml6YXRpb24xGzAZBgNVBAMTEnRlc3QyMi5leGFtcGxlLmNvbTBcMA0GCSqG
SIb3DQEBAQUAA0sAMEgCQQCwj671EqiHW+JWDcZRlSEpNWYn0fn1h377RRsPjPo+
K3Q4mvF2CITPJczAjuMDNwYKUUkK4BwwTlPDKr/ChzADAgMBAAGjQjBAMA4GA1Ud
DwEB/wQEAwIChDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0T
AQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAANBAFRzCc1dHVSOxnM2zA5Fjo0YceL1
xsRA9/ZP/g6wrVkQVhWf1g6CzDMk07F5yRujdPMKLYVIC/Rt2hCP/F8XZS8=
-----END CERTIFICATE-----
`

func Test_Verify(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    ok, err := New().Verify(caRoot2, ca2, VerifyOptions{
        Intermediates: cryptobin_x509.NewCertPool(),
    })

    assertNoError(err, "Test_Verify")
    assertEqual(ok, true, "Test_Verify")
}

func Test_Get(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    cert := New().
        FromCertificate([]byte(cert)).
        GetCert()

    csr := New().
        FromCertificateRequest([]byte(csrCert)).
        GetCertRequest()

    privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
    publicKey := &privateKey.PublicKey

    testerr := errors.New("test-error")
    opts := Options{
        PublicKeyType:  KeyTypeRSA,
        ParameterSizes: dsa.L1024N160,
        Curve:          elliptic.P256(),
        GostCurve:      gost.CurveIdGostR34102001CryptoProAParamSet(),
        Bits:           2048,
        Bitsize:        256,
        Probability:    64,
    }

    newCA2 := CA{
        cert:        cert,
        certRequest: csr,
        privateKey:  privateKey,
        publicKey:   publicKey,
        options:     opts,
        keyData:     []byte("test-keyData"),
        Errors:      []error{testerr},
    }

    assertEqual(newCA2.GetCert(), cert, "Test_Get-GetCert")
    assertEqual(newCA2.GetCertRequest(), csr, "Test_Get-GetCertRequest")

    assertEqual(newCA2.GetPrivateKey(), privateKey, "Test_Get-GetPrivateKey")
    assertEqual(newCA2.GetPrivateKeyType().String(), "RSA", "Test_Get-GetPrivateKeyType")

    assertEqual(newCA2.GetPublicKey(), publicKey, "Test_Get-GetPublicKey")
    assertEqual(newCA2.GetPublicKeyType().String(), "RSA", "Test_Get-GetPublicKeyType")

    assertEqual(newCA2.GetOptions(), opts, "Test_Get-GetOptions")
    assertEqual(newCA2.GetParameterSizes(), dsa.L1024N160, "Test_Get-GetParameterSizes")
    assertEqual(newCA2.GetCurve(), elliptic.P256(), "Test_Get-GetCurve")
    assertEqual(newCA2.GetGostCurve(), gost.CurveIdGostR34102001CryptoProAParamSet(), "Test_Get-GetGostCurve")
    assertEqual(newCA2.GetBits(), 2048, "Test_Get-GetBits")
    assertEqual(newCA2.GetBitsize(), 256, "Test_Get-GetBitsize")
    assertEqual(newCA2.GetProbability(), 64, "Test_Get-GetProbability")

    assertEqual(newCA2.GetKeyData(), []byte("test-keyData"), "Test_Get-GetKeyData")
    assertEqual(newCA2.GetErrors(), []error{testerr}, "Test_Get-GetErrors")

    assertEqual(newCA2.ToKeyBytes(), []byte("test-keyData"), "Test_Get-ToKeyBytes")
    assertEqual(newCA2.ToKeyString(), "test-keyData", "Test_Get-ToKeyString")
}

func Test_With(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    cert := New().
        FromCertificate([]byte(cert)).
        GetCert()

    csr := New().
        FromCertificateRequest([]byte(csrCert)).
        GetCertRequest()

    privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
    publicKey := &privateKey.PublicKey

    testerr := errors.New("test-error")
    opts := Options{
        PublicKeyType:  KeyTypeRSA,
        ParameterSizes: dsa.L1024N160,
        Curve:          elliptic.P256(),
        Bits:           2048,
    }

    var tmp CA

    newCA := CA{}

    tmp = newCA.WithCert(cert)
    assertEqual(tmp.cert, cert, "Test_Get-WithCert")

    tmp = newCA.WithCertRequest(csr)
    assertEqual(tmp.certRequest, csr, "Test_Get-WithCertRequest")

    tmp = newCA.WithPrivateKey(privateKey)
    assertEqual(tmp.privateKey, privateKey, "Test_Get-WithPrivateKey")

    tmp = newCA.WithPublicKey(publicKey)
    assertEqual(tmp.publicKey, publicKey, "Test_Get-WithPublicKey")

    tmp = newCA.WithOptions(opts)
    assertEqual(tmp.options, opts, "Test_Get-WithOptions")

    tmp = newCA.WithPublicKeyType(KeyTypeRSA)
    assertEqual(tmp.options.PublicKeyType, KeyTypeRSA, "Test_Get-WithPublicKeyType")

    tmp = newCA.SetPublicKeyType("ECDSA")
    assertEqual(tmp.options.PublicKeyType, KeyTypeECDSA, "Test_Get-SetPublicKeyType")

    tmp = newCA.SetGenerateType("EdDSA")
    assertEqual(tmp.options.PublicKeyType, KeyTypeEdDSA, "Test_Get-SetGenerateType")

    tmp = newCA.WithParameterSizes(dsa.L1024N160)
    assertEqual(tmp.options.ParameterSizes, dsa.L1024N160, "Test_Get-WithParameterSizes")

    tmp = newCA.SetParameterSizes("L2048N224")
    assertEqual(tmp.options.ParameterSizes, dsa.L2048N224, "Test_Get-SetParameterSizes")

    tmp = newCA.WithCurve(elliptic.P384())
    assertEqual(tmp.options.Curve, elliptic.P384(), "Test_Get-WithCurve")

    tmp = newCA.SetCurve("P521")
    assertEqual(tmp.options.Curve, elliptic.P521(), "Test_Get-SetCurve")

    tmp = newCA.WithGostCurve(gost.CurveIdtc26gost34102012256paramSetB())
    assertEqual(tmp.options.GostCurve, gost.CurveIdtc26gost34102012256paramSetB(), "Test_Get-WithGostCurve")

    tmp = newCA.SetGostCurve("IdGostR34102001CryptoProXchBParamSet")
    assertEqual(tmp.options.GostCurve, gost.CurveIdGostR34102001CryptoProXchBParamSet(), "Test_Get-SetGostCurve")

    tmp = newCA.WithBits(2048)
    assertEqual(tmp.options.Bits, 2048, "Test_Get-WithBits")

    tmp = newCA.WithBitsize(2038)
    assertEqual(tmp.options.Bitsize, 2038, "Test_Get-WithBitsize")

    tmp = newCA.WithProbability(2028)
    assertEqual(tmp.options.Probability, 2028, "Test_Get-WithProbability")

    tmp = newCA.WithKeyData([]byte("test-keyData"))
    assertEqual(tmp.keyData, []byte("test-keyData"), "Test_Get-WithKeyData")

    tmp = newCA.WithErrors([]error{testerr})
    assertEqual(tmp.Errors, []error{testerr}, "Test_Get-WithErrors")
}
