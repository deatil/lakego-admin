package ca

import (
    "testing"
    "encoding/pem"
    "crypto/x509/pkix"

    cryptobin_x509 "github.com/deatil/go-cryptobin/x509"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_CreateCA(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := New().
        SetPublicKeyType("RSA").
        WithBits(512).
        GenerateKey().
        MakeCA(pkix.Name{
            CommonName:   "test.example.com",
            Organization: []string{"Test"},
        }, 2, "SHA256WithRSA").
        CreateCA()
    key := obj.ToKeyString()

    assertError(obj.Error(), "Test_CreateCA")
    assertNotEmpty(key, "Test_CreateCA")

    // ===========

    block, _ := pem.Decode([]byte(key))

    cert, err := cryptobin_x509.ParseCertificate(block.Bytes)
    if err != nil {
        t.Fatal("failed to read cert file")
    }

    err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
    if err != nil {
        t.Fatal(err)
    }
}

func Test_GenerateKey(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    t.Run("GenerateRSAKey", func(t *testing.T) {
        obj := New().
            SetPublicKeyType("RSA").
            WithBits(2048).
            GenerateKey()

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertError(obj.Error(), "Test_GenerateKey")
        assertNotEmpty(prikey, "Test_GenerateKey-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey-pubkey")

        pass := []byte("12345678")
        prikey2 := obj.CreatePrivateKeyWithPassword(pass).ToKeyString()

        assertNotEmpty(prikey2, "Test_GenerateKey-prikey2")
    })

    t.Run("GenerateDSAKey", func(t *testing.T) {
        obj := New().
            SetPublicKeyType("DSA").
            SetParameterSizes("L1024N160").
            GenerateKey()

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertError(obj.Error(), "Test_GenerateKey")
        assertNotEmpty(prikey, "Test_GenerateKey-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey-pubkey")

        pass := []byte("12345678")
        prikey2 := obj.CreatePrivateKeyWithPassword(pass).ToKeyString()

        assertNotEmpty(prikey2, "Test_GenerateKey-prikey2")
    })

    t.Run("GenerateECDSAKey", func(t *testing.T) {
        obj := New().
            SetPublicKeyType("ECDSA").
            SetCurve("P256").
            GenerateKey()

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertError(obj.Error(), "Test_GenerateKey")
        assertNotEmpty(prikey, "Test_GenerateKey-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey-pubkey")

        pass := []byte("12345678")
        prikey2 := obj.CreatePrivateKeyWithPassword(pass).ToKeyString()

        assertNotEmpty(prikey2, "Test_GenerateKey-prikey2")
    })

    t.Run("GenerateEdDSAKey", func(t *testing.T) {
        obj := New().
            SetPublicKeyType("EdDSA").
            GenerateKey()

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertError(obj.Error(), "Test_GenerateKey")
        assertNotEmpty(prikey, "Test_GenerateKey-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey-pubkey")

        pass := []byte("12345678")
        prikey2 := obj.CreatePrivateKeyWithPassword(pass).ToKeyString()

        assertNotEmpty(prikey2, "Test_GenerateKey-prikey2")
    })

    t.Run("GenerateSM2Key", func(t *testing.T) {
        obj := New().
            SetPublicKeyType("SM2").
            GenerateKey()

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertError(obj.Error(), "Test_GenerateKey")
        assertNotEmpty(prikey, "Test_GenerateKey-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey-pubkey")

        pass := []byte("12345678")
        prikey2 := obj.CreatePrivateKeyWithPassword(pass).ToKeyString()

        assertNotEmpty(prikey2, "Test_GenerateKey-prikey2")
    })

    t.Run("GenerateRSAKey 2", func(t *testing.T) {
        obj := New().
            SetGenerateType("RSA").
            WithBits(2048).
            GenerateKey()

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertError(obj.Error(), "Test_GenerateKey")
        assertNotEmpty(prikey, "Test_GenerateKey-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey-pubkey")

        pass := []byte("12345678")
        prikey2 := obj.CreatePrivateKeyWithPassword(pass).ToKeyString()

        assertNotEmpty(prikey2, "Test_GenerateKey-prikey2")
    })

}

func Test_GenerateKey2(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    t.Run("GenerateRSAKey", func(t *testing.T) {
        obj := New().
            GenerateRSAKey(2048)

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertError(obj.Error(), "Test_GenerateKey2")
        assertNotEmpty(prikey, "Test_GenerateKey2-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey2-pubkey")
    })

    t.Run("GenerateDSAKey", func(t *testing.T) {
        obj := New().GenerateDSAKey("L2048N224")

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertError(obj.Error(), "Test_GenerateKey2")
        assertNotEmpty(prikey, "Test_GenerateKey2-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey2-pubkey")
    })

    t.Run("GenerateECDSAKey", func(t *testing.T) {
        obj := New().
            GenerateECDSAKey("P256")

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertError(obj.Error(), "Test_GenerateKey2")
        assertNotEmpty(prikey, "Test_GenerateKey2-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey2-pubkey")
    })

    t.Run("GenerateEdDSAKey", func(t *testing.T) {
        obj := New().
            GenerateEdDSAKey()

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertError(obj.Error(), "Test_GenerateKey2")
        assertNotEmpty(prikey, "Test_GenerateKey2-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey2-pubkey")
    })

    t.Run("GenerateSM2Key", func(t *testing.T) {
        obj := New().
            GenerateSM2Key()

        prikey := obj.CreatePrivateKey().ToKeyString()
        pubkey := obj.CreatePublicKey().ToKeyString()

        assertError(obj.Error(), "Test_GenerateKey2")
        assertNotEmpty(prikey, "Test_GenerateKey2-prikey")
        assertNotEmpty(pubkey, "Test_GenerateKey2-pubkey")
    })

}
