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
        GenerateRSAKey(512).
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
