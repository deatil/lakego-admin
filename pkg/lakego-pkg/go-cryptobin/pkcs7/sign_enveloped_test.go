package pkcs7

import (
    "bytes"
    "testing"
    "math/big"
    "encoding/pem"
    "crypto/ecdsa"

    "github.com/deatil/go-cryptobin/x509"
    "github.com/deatil/go-cryptobin/gm/sm2"
)

func Test_ParseSignedEvnvelopedData(t *testing.T) {
    var block *pem.Block
    block, rest := pem.Decode([]byte(smSignedEvelopedTestData))
    if len(rest) != 0 {
        t.Fatal("unexpected remaining PEM block during decode")
    }
    p7Data, err := Parse(block.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    if len(p7Data.Certificates) != 1 {
        t.Fatal("should only one certificate")
    }

    block, rest = pem.Decode([]byte(signKey))
    if len(rest) != 0 {
        t.Fatal("unexpected remaining PEM block during decode")
    }

    sm2SignPriv, err := sm2.ParsePrivateKey(block.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    block, rest = pem.Decode([]byte(signCert))
    if len(rest) != 0 {
        t.Fatal("unexpected remaining PEM block during decode")
    }

    signCertificate, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    if !sm2SignPriv.PublicKey.Equal(signCertificate.PublicKey) {
        t.Fatal("not one key pair")
    }

    err = p7Data.DecryptOnlyOne(sm2SignPriv)
    if err != nil {
        t.Fatal(err)
    }

    encKeyBytes := p7Data.Content

    err = p7Data.Verify()
    if err != nil {
        t.Fatal(err)
    }

    block, rest = pem.Decode([]byte(expectedEncKey))
    if len(rest) != 0 {
        t.Fatal("unexpected remaining PEM block during decode")
    }

    sm2EncPriv, err := sm2.ParsePrivateKey(block.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    if new(big.Int).SetBytes(encKeyBytes).Cmp(sm2EncPriv.D) != 0 {
        t.Fatalf("the priv key is not same, got %x, expected %x", encKeyBytes, sm2EncPriv.D.Bytes())
    }
}

func Test_CreateSignedEvnvelopedDataWithSM2(t *testing.T) {
    rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, x509.SM2WithSM3, true)
    if err != nil {
        t.Fatal(err)
    }

    recipient, err := createTestCertificateByIssuer("PKCS7 Test Recipient", rootCert, x509.SM2WithSM3, false)
    if err != nil {
        t.Fatal(err)
    }

    encryptKey, err := createTestCertificateByIssuer("PKCS7 Test Encrypt Key", rootCert, x509.SM2WithSM3, false)
    if err != nil {
        t.Fatal(err)
    }

    privKey := make([]byte, 32)
    sm2Key, ok := (*encryptKey.PrivateKey).(*sm2.PrivateKey)
    if !ok {
        t.Fatal("should be sm2 private key")
    }

    sm2Key.D.FillBytes(privKey)

    testCipers := []Cipher{SM4ECB, SM4CBC, SM4GCM}
    for _, cipher := range testCipers {
        saed, err := NewSMSignedAndEnvelopedData(privKey, cipher)
        if err != nil {
            t.Fatal(err)
        }

        err = saed.AddSigner(rootCert.Certificate, *rootCert.PrivateKey)
        if err != nil {
            t.Fatal(err)
        }

        err = saed.AddRecipient(recipient.Certificate)
        if err != nil {
            t.Fatal(err)
        }
        result, err := saed.Finish()
        if err != nil {
            t.Fatal(err)
        }

        // parse, decrypt, verify
        p7Data, err := Parse(result)
        if err != nil {
            t.Fatal(err)
        }

        err = p7Data.Decrypt(recipient.Certificate, *recipient.PrivateKey)
        if err != nil {
            t.Fatal(err)
        }

        err = p7Data.Verify()
        if err != nil {
            t.Fatal(err)
        }

        if !bytes.Equal(p7Data.Content, privKey) {
            t.Fatal("not same private key")
        }
    }
}

func Test_CreateSignedEvnvelopedData(t *testing.T) {
    rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, x509.ECDSAWithSHA256, true)
    if err != nil {
        t.Fatal(err)
    }
    recipient, err := createTestCertificateByIssuer("PKCS7 Test Recipient", rootCert, x509.SHA256WithRSA, false)
    if err != nil {
        t.Fatal(err)
    }
    unsupportRecipient, err := createTestCertificateByIssuer("PKCS7 Test Unsupport Recipient", rootCert, x509.ECDSAWithSHA256, false)
    if err != nil {
        t.Fatal(err)
    }

    encryptKey, err := createTestCertificateByIssuer("PKCS7 Test Encrypt Key", rootCert, x509.ECDSAWithSHA256, false)
    if err != nil {
        t.Fatal(err)
    }
    privKey := make([]byte, 32)
    ecdsaKey, ok := (*encryptKey.PrivateKey).(*ecdsa.PrivateKey)
    if !ok {
        t.Fatal("should be ecdsa private key")
    }
    ecdsaKey.D.FillBytes(privKey)

    testCipers := []Cipher{AES256CBC, AES256GCM}
    for _, cipher := range testCipers {
        saed, err := NewSignedAndEnvelopedData(privKey, cipher)
        if err != nil {
            t.Fatal(err)
        }
        saed.SetDigestAlgorithm(OidDigestAlgorithmSHA256)
        err = saed.AddSigner(rootCert.Certificate, *rootCert.PrivateKey)
        if err != nil {
            t.Fatal(err)
        }
        err = saed.AddRecipient(recipient.Certificate)
        if err != nil {
            t.Fatal(err)
        }
        if err = saed.AddRecipient(unsupportRecipient.Certificate); err.Error() != "go-cryptobin/pkcs7: only supports RSA/SM2 key" {
            t.Fatal("not expected error message")
        }

        result, err := saed.Finish()
        if err != nil {
            t.Fatal(err)
        }

        // parse, decrypt, verify
        p7Data, err := Parse(result)
        if err != nil {
            t.Fatal(err)
        }

        err = p7Data.Decrypt(recipient.Certificate, *recipient.PrivateKey)
        if err != nil {
            t.Fatal(err)
        }

        err = p7Data.Verify()
        if err != nil {
            t.Fatal(err)
        }

        if !bytes.Equal(p7Data.Content, privKey) {
            t.Fatal("not same private key")
        }
    }
}
