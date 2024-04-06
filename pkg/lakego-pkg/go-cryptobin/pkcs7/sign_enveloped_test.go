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

// from https://www.gmcert.org/
var smSignedEvelopedTestData = `-----BEGIN PKCS7-----
MIIDwwYKKoEcz1UGAQQCBKCCA7MwggOvAgEBMYGfMIGcAgEBMAwAAAIIAs64zJDL
T8UwCwYJKoEcz1UBgi0DBHwwegIhAPbXLhqtkA/HeYKgPeZNPP4kT2/PqS7K8NiB
vAFCBsf+AiEA4m9ZyghfFUaE1K4kre9T/R7Td4hVQPij9GOloRykKJ8EIMJ/zBGe
WaqgtCUFu99S3Wovtd6+jN1tDkTJPWgZ6uu1BBCobCvaWMr0Of+Z686i/wVrMQww
CgYIKoEcz1UBgxEwWQYKKoEcz1UGAQQCATAJBgcqgRzPVQFogEDM1pUC/MDTCRCQ
uZiIxZYZzNaVAvzA0wkQkLmYiMWWGUnT7MvXe2M2khckxgU+ZMVBNDpf4EFl6+C2
PRPcy8ROoIIB4jCCAd4wggGDoAMCAQICCALODAD8KSAXMAoGCCqBHM9VAYN1MEIx
CzAJBgNVBAYTAkNOMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njER
MA8GA1UECgwI5rWL6K+VQ0EwHhcNMjExMjIzMDg0ODMzWhcNMzExMjIzMDg0ODMz
WjBCMQswCQYDVQQGEwJDTjEPMA0GA1UECAwG5rWZ5rGfMQ8wDQYDVQQHDAbmna3l
t54xETAPBgNVBAoMCOa1i+ivlUNBMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE
SrOgeWQcu+dzrGUniH7/M0nG4ol5C4wfj5cPmFr6HrEZKmBnvzKo6/K65k4auohF
rm2CumYkEFeeJCpXL2tx7aNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQF
MAMBAf8wHQYDVR0OBBYEFDaT4xTnRQn61e/qLxIt06GWPMKkMB8GA1UdIwQYMBaA
FDaT4xTnRQn61e/qLxIt06GWPMKkMAoGCCqBHM9VAYN1A0kAMEYCIQCw4bSylc4l
IV203nQ6L0QDUgnbugidDAMO1m5d7wFhjgIhAMwly3Bd9gzOQM3vTKqVH0H2D2kU
y2JDcEl5cPy1GBOhMYG4MIG1AgEBME4wQjELMAkGA1UEBhMCQ04xDzANBgNVBAgM
Bua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQKDAjmtYvor5VDQQIIAs4M
APwpIBcwCgYIKoEcz1UBgxEwCwYJKoEcz1UBgi0BBEcwRQIgR7STVlgH/yy4k93+
h3KRFN+dWEVeOJ7G1lRRSNXihnkCIQCHxZvmdUcv38SBCgZp+qxnpm2a+C1/tWKV
d/A8tW8dnw==
-----END PKCS7-----
`

var encCert = `-----BEGIN CERTIFICATE-----
MIICPTCCAeOgAwIBAgIIAs64zJDLT8UwCgYIKoEcz1UBg3UwQjELMAkGA1UEBhMC
Q04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQKDAjm
tYvor5VDQTAeFw0yMzAyMjIxMjIwMzNaFw0yNDAyMjIxMjIwMzNaMH0xCzAJBgNV
BAYTAkNOMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njEVMBMGA1UE
CgwM5rWL6K+V5py65p6EMRUwEwYDVQQLDAzmtYvor5Xnu4Tnu4cxHjAcBgNVBAMM
Fea1i+ivleacjeWKoeWZqOWQjeensDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IA
BGqelO/A74LrAZvxFopkSz9lpjygTF1ffslhB0BzwxQ5jMx1D4912Swb6foMe+0k
bq9V2i3Kn2HrzSTAcj+G+9ujgYcwgYQwDgYDVR0PAQH/BAQDAgM4MBMGA1UdJQQM
MAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFDd41c6+e9aahmQD
PdC8YSXfwYgUMB8GA1UdIwQYMBaAFDaT4xTnRQn61e/qLxIt06GWPMKkMA8GA1Ud
EQQIMAaHBH8AAAEwCgYIKoEcz1UBg3UDSAAwRQIgMZBhweovXaHVNSlLv0rTEYnT
GRSsTKmrkCDrxQdaWVUCIQCqeAiXqEnwcdOb6DTFxKF2E2htppt7H4y1K8UVmF7s
eg==
-----END CERTIFICATE-----
`

var signCert = `-----BEGIN CERTIFICATE-----
MIICPTCCAeOgAwIBAgIIAs64zJDLTNQwCgYIKoEcz1UBg3UwQjELMAkGA1UEBhMC
Q04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQKDAjm
tYvor5VDQTAeFw0yMzAyMjIxMjIwMzNaFw0yNDAyMjIxMjIwMzNaMH0xCzAJBgNV
BAYTAkNOMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njEVMBMGA1UE
CgwM5rWL6K+V5py65p6EMRUwEwYDVQQLDAzmtYvor5Xnu4Tnu4cxHjAcBgNVBAMM
Fea1i+ivleacjeWKoeWZqOWQjeensDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IA
BL4bEPQAKg3aEjsXsnEm4tSFOetUMYzUpLJyYKc0isNwiu8fNBZAihjDOVzQ3FQf
BeZXJdxvbdC5s22m1E81mwSjgYcwgYQwDgYDVR0PAQH/BAQDAgbAMBMGA1UdJQQM
MAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFBGRF+xJjaBurdse
flfRaPUcBjFWMB8GA1UdIwQYMBaAFDaT4xTnRQn61e/qLxIt06GWPMKkMA8GA1Ud
EQQIMAaHBH8AAAEwCgYIKoEcz1UBg3UDSAAwRQIhAKfa/H/f2OgTXhipfEPXPiHb
nZFJyugnvKFkrijK8Qp5AiARlYEA2FR21H43/e/qu2lrp+ZUeYk3ve8nMd3yua9L
Ag==
-----END CERTIFICATE-----
`

var signKey = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQg1FlRx/WjmIFZ5dV4
ghl1JwHIfMdGKLvYdPd1akXUCQSgCgYIKoEcz1UBgi2hRANCAAS+GxD0ACoN2hI7
F7JxJuLUhTnrVDGM1KSycmCnNIrDcIrvHzQWQIoYwzlc0NxUHwXmVyXcb23QubNt
ptRPNZsE
-----END PRIVATE KEY-----
`

var expectedEncKey = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgyhwdf0K3AnMCLEbG
B1yMjJLLlfQkGE53dvCPttt1BkCgCgYIKoEcz1UBgi2hRANCAARqnpTvwO+C6wGb
8RaKZEs/ZaY8oExdX37JYQdAc8MUOYzMdQ+PddksG+n6DHvtJG6vVdotyp9h680k
wHI/hvvb
-----END PRIVATE KEY-----
`

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
        saed, err := NewSignedAndEnvelopedData(privKey, cipher)
        if err != nil {
            t.Fatal(err)
        }

        saed.SetMode(SM2Mode)
        saed.SetDigestAlgorithm(OidDigestAlgorithmSM3)

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
        if err = saed.AddRecipient(unsupportRecipient.Certificate); err.Error() != "pkcs7: only supports RSA/SM2 key" {
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
