package pkcs7

import (
    // "os"
    "fmt"
    "time"
    "bytes"
    "testing"
    "crypto"
    "crypto/rsa"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/gm/sm2"
    cryptobin_x509 "github.com/deatil/go-cryptobin/x509"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func encodePEM(src []byte, typ string) string {
    keyBlock := &pem.Block{
        Type:  typ,
        Bytes: src,
    }

    keyData := pem.EncodeToMemory(keyBlock)

    return string(keyData)
}

func decodePEM(p string) []byte {
    b, _ := pem.Decode([]byte(p))
    return b.Bytes
}

func decodeCert(p string) *cryptobin_x509.Certificate {
    der := decodePEM(p)
    cert, _ := cryptobin_x509.ParseCertificate(der)
    return cert
}

func decodePrivateKey(p string) any {
    der := decodePEM(p)
    parsedKey, _ := x509.ParsePKCS8PrivateKey(der)
    return parsedKey
}

func decodeSM2PrivateKey(p string) any {
    der := decodePEM(p)
    parsedKey, _ := sm2.ParsePrivateKey(der)
    return parsedKey
}

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
MIICejCCAiCgAwIBAgIIAs64zJDLTNQwCgYIKoEcz1UBg3UwfTELMAkGA1UEBhMC
Q04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMRUwEwYDVQQKDAzm
tYvor5XmnLrmnoQxFTATBgNVBAsMDOa1i+ivlee7hOe7hzEeMBwGA1UEAwwV5rWL
6K+V5pyN5Yqh5Zmo5ZCN56ewMCAXDTI0MDQwNzAzNDYwOFoYDzIwNzQwNDA3MDM0
NjA4WjB9MQswCQYDVQQGEwJDTjEPMA0GA1UECAwG5rWZ5rGfMQ8wDQYDVQQHDAbm
na3lt54xFTATBgNVBAoMDOa1i+ivleacuuaehDEVMBMGA1UECwwM5rWL6K+V57uE
57uHMR4wHAYDVQQDDBXmtYvor5XmnI3liqHlmajlkI3np7AwWTATBgcqhkjOPQIB
BggqgRzPVQGCLQNCAAS+GxD0ACoN2hI7F7JxJuLUhTnrVDGM1KSycmCnNIrDcIrv
HzQWQIoYwzlc0NxUHwXmVyXcb23QubNtptRPNZsEo4GHMIGEMA4GA1UdDwEB/wQE
AwIGwDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQW
BBQRkRfsSY2gbq3bHn5X0Wj1HAYxVjAfBgNVHSMEGDAWgBQ2k+MU50UJ+tXv6i8S
LdOhljzCpDAPBgNVHREECDAGhwR/AAABMAoGCCqBHM9VAYN1A0gAMEUCIQDRrd5F
nyZtlFbibpLmfbb/vjNOA7DoCn8U/oIkPh+JHQIgUD+lWSCA2TUpsz0oppacXb8q
/Zk9xZk7sEs7LyYFscE=
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

func test_UpdateCertTime(t *testing.T) {
    template := decodeCert(signCert)
    template.NotBefore = time.Now()
    template.NotAfter = time.Now().AddDate(50, 0, 0)

    pubKey := template.PublicKey
    privKey := decodeSM2PrivateKey(signKey)

    cert, err := cryptobin_x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
    if err != nil {
        t.Fatal("failed to create cert file")
    }

    certpem := encodePEM(cert, "CERTIFICATE")

    t.Errorf("new cert: %s \n", certpem)
}

// =========

var testEncryptedTestCertificate = `-----BEGIN CERTIFICATE-----
MIICZTCCAc6gAwIBAgIQAOj+a/ymkrFvZ7V3lPauczANBgkqhkiG9w0BAQsFADAV
MRMwEQYDVQQDDApnaXRodWIuY29tMB4XDTIyMDgxNTAxMzMwMFoXDTMyMDgxMjAx
MzMwMFowFTETMBEGA1UEAwwKZ2l0aHViLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOB
jQAwgYkCgYEAh14P1kkrUkAK9FI6fanvihmrZUeLMOnmVu/MIIPjYpb+RgwB6drT
fpd4e3l9TzLCmyUxEkGAscBFnCJCpkyKtqLgwifODu0GgsFFGxx16DXdO5ocmATg
EJu7PpFMau2hmBP1fM996+8Y31S2C1TDOQc3BRVgYY2tH+CZhD500IkCAwEAAaOB
tTCBsjAVBgNVHREEDjAMggpnaXRodWIuY29tMB0GA1UdDgQWBBR86aCAQbFkmaoZ
Meok34ooA6Dw4TAOBgNVHQ8BAf8EBAMCBLAwDAYDVR0TAQH/BAIwADA7BgNVHSUE
NDAyBggrBgEFBQcDAgYIKwYBBQUHAwEGCCsGAQUFBwMDBggrBgEFBQcDBAYIKwYB
BQUHAwgwHwYDVR0jBBgwFoAUfOmggEGxZJmqGTHqJN+KKAOg8OEwDQYJKoZIhvcN
AQELBQADgYEAFwJauQxug33ahfshzjQ7tBK8wCjOH/ajqVqyzHxnf3aqUXwqlEOq
wA/9amAulE6TGOuZJKCwjpCHOkgeHQaks+QlH0/8lEnOoyfT8rWl3DQn4s52OSr2
okTTUcSJyRUA6PyhnVVIKgEmKJ3CSJSOrczbBrs4meYdRebbaOFVlY8=
-----END CERTIFICATE-----`

var testEncryptedTestPrivateKey = `-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIdeD9ZJK1JACvRS
On2p74oZq2VHizDp5lbvzCCD42KW/kYMAena036XeHt5fU8ywpslMRJBgLHARZwi
QqZMirai4MInzg7tBoLBRRscdeg13TuaHJgE4BCbuz6RTGrtoZgT9XzPfevvGN9U
tgtUwzkHNwUVYGGNrR/gmYQ+dNCJAgMBAAECgYAYygtpaP3TcqHu6w4GDDQvHJNM
GUVuoC7L1d8SR0TBPbhz2GgTTLz1TkTEi9N8SOXlZnKtjqxEINs+g/GjpZmzIzm3
R8sNmFA0PBcy9xGFBT0TBe3VD9bnPWXOCA6ONibZ8iwv8xwMTRIABgP+hRyy+jvr
KYpZBgpTsl6ssZxjmQJBAMB3N0fCurcKqylQHX3gb0w69jWvTCaYc/S+ypjMeC6m
TIrnPXlD1/m5WK16fn6hMUA6ahFuRZYgoktoYXdc9w0CQQC0DZ4rJzBueL4r+4m8
I0mQT0dNIw4ffQL1WqPcaobJfw1w+HHiWRr2jPKYxSHW7Zu9J9AhMJtS+afmDG9h
diBtAkEAkxNHAiZzimazr2lScBuu0WEJPrMLjT7Y9YFKzoMJoBRiz46vslg+1c1m
T4MY4OmK+lrpLRLISFX9z4QfXxiCjQJAdodsc04GJQNZdczOPEsil1yJPK9yEaqT
Mv+rVWPPPYBlUdRL7EzqYhohbg6AG2QqHRjDe8XqynHNZLUU8Zz49QJAQpBx4AMg
eCRSVO98IPeKakI0HnOboO7AcAx8waOgz9x3jdnwZojAbAGDUg/NWGXrDV7ffIjY
HYjNDaIbnlqN9g==
-----END PRIVATE KEY-----`

func signAndDetach(content []byte, cert *cryptobin_x509.Certificate, privkey *rsa.PrivateKey) (signed []byte, err error) {
    toBeSigned, err := NewSignedData(content)
    if err != nil {
        err = fmt.Errorf("Cannot initialize signed data: %s", err)
        return
    }
    if err = toBeSigned.AddSigner(cert, privkey, SignerInfoConfig{}); err != nil {
        err = fmt.Errorf("Cannot add signer: %s", err)
        return
    }

    // Detach signature, omit if you want an embedded signature
    toBeSigned.Detach()

    signed, err = toBeSigned.Finish()
    if err != nil {
        err = fmt.Errorf("Cannot finish signing data: %s", err)
        return
    }

    // Verify the signature
    // pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})

    p7, err := Parse(signed)
    if err != nil {
        err = fmt.Errorf("Cannot parse our signed data: %s", err)
        return
    }

    // since the signature was detached, reattach the content here
    p7.Content = content

    if bytes.Compare(content, p7.Content) != 0 {
        err = fmt.Errorf("Our content was not in the parsed data:\n\tExpected: %s\n\tActual: %s", content, p7.Content)
        return
    }
    if err = p7.Verify(); err != nil {
        err = fmt.Errorf("Cannot verify our signed data: %s", err)
        return
    }

    // 加密
    key := []byte("123456789012werfde1234567890rt32")
    enData, err := EncryptUsingPSK(rand.Reader, signed, key, AES256CBC)
    enDataw := EncodePkcs7ToPem(enData, "ENCRYPTED PKCS7")

    // 解密
    deData, _ := ParsePkcs7Pem(enDataw)
    deDataw, err := DecryptUsingPSK(deData, key)

    if string(signed) != string(deDataw) {
        err = fmt.Errorf("Cannot Decrypt our signed data: %s", err)
        return
    }

    return deDataw, err
}

func Test_SignAndDetach(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    cert := decodeCert(testEncryptedTestCertificate)
    parsedKey := decodePrivateKey(testEncryptedTestPrivateKey)
    privateKey := parsedKey.(*rsa.PrivateKey)

    pkcs7Sign, pkcs7err := signAndDetach([]byte("hello world"), cert, privateKey)

    assertError(pkcs7err, "SignAndDetach-Decode")

    assertNotEmpty(pkcs7Sign, "SignAndDetach")
}

func signAndDetach2(content []byte, cert *cryptobin_x509.Certificate, privkey *rsa.PrivateKey) (signed []byte, err error) {
    toBeSigned, err := NewSignedData(content)
    if err != nil {
        err = fmt.Errorf("Cannot initialize signed data: %s", err)
        return
    }
    if err = toBeSigned.AddSigner(cert, privkey, SignerInfoConfig{}); err != nil {
        err = fmt.Errorf("Cannot add signer: %s", err)
        return
    }

    // Detach signature, omit if you want an embedded signature
    toBeSigned.Detach()

    signed, err = toBeSigned.Finish()
    if err != nil {
        err = fmt.Errorf("Cannot finish signing data: %s", err)
        return
    }

    // Verify the signature
    // pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})

    p7, err := Parse(signed)
    if err != nil {
        err = fmt.Errorf("Cannot parse our signed data: %s", err)
        return
    }

    // since the signature was detached, reattach the content here
    p7.Content = content

    if bytes.Compare(content, p7.Content) != 0 {
        err = fmt.Errorf("Our content was not in the parsed data:\n\tExpected: %s\n\tActual: %s", content, p7.Content)
        return
    }
    if err = p7.Verify(); err != nil {
        err = fmt.Errorf("Cannot verify our signed data: %s", err)
        return
    }

    // 加密
    enData, err := Encrypt(rand.Reader, signed, []*cryptobin_x509.Certificate{cert})
    enDataw := EncodePkcs7ToPem(enData, "ENCRYPTED PKCS7")

    // 解密
    deData, _ := ParsePkcs7Pem(enDataw)
    deDataw, err := Decrypt(deData, cert, privkey)

    if string(signed) != string(deDataw) {
        err = fmt.Errorf("Cannot Decrypt our signed data: %s", err)
        return
    }

    return deDataw, err
}

func Test_SignAndDetach2(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    cert := decodeCert(testEncryptedTestCertificate)
    parsedKey := decodePrivateKey(testEncryptedTestPrivateKey)
    privateKey := parsedKey.(*rsa.PrivateKey)

    pkcs7Sign, pkcs7err := signAndDetach2([]byte("hello world"), cert, privateKey)

    assertError(pkcs7err, "SignAndDetach2-Decode")

    assertNotEmpty(pkcs7Sign, "SignAndDetach2")
}

// =========

func signWithAlgorithm(
    content []byte,
    cert *cryptobin_x509.Certificate,
    privkey crypto.PrivateKey,
    dOid asn1.ObjectIdentifier,
    eOid asn1.ObjectIdentifier,
) (signed []byte, err error) {
    toBeSigned, err := NewSignedData(content)
    if err != nil {
        err = fmt.Errorf("Cannot initialize signed data: %s", err)
        return
    }

    toBeSigned.SetDigestAlgorithm(dOid)
    toBeSigned.SetEncryptionAlgorithm(eOid)

    if err = toBeSigned.AddSigner(cert, privkey, SignerInfoConfig{}); err != nil {
        err = fmt.Errorf("Cannot add signer: %s", err)
        return
    }

    // Detach signature, omit if you want an embedded signature
    toBeSigned.Detach()

    signed, err = toBeSigned.Finish()
    if err != nil {
        err = fmt.Errorf("Cannot finish signing data: %s", err)
        return
    }

    // Verify the signature
    // pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})

    p7, err := Parse(signed)
    if err != nil {
        err = fmt.Errorf("Cannot parse our signed data: %s", err)
        return
    }

    // since the signature was detached, reattach the content here
    p7.Content = content

    if bytes.Compare(content, p7.Content) != 0 {
        err = fmt.Errorf("Our content was not in the parsed data:\n\tExpected: %s\n\tActual: %s", content, p7.Content)
        return
    }
    if err = p7.Verify(); err != nil {
        err = fmt.Errorf("Cannot verify our signed data: %s", err)
        return
    }

    return
}

func Test_SignWithAlgorithm(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    cert := decodeCert(testEncryptedTestCertificate)
    privateKey := decodePrivateKey(testEncryptedTestPrivateKey)

    certSM := decodeCert(signCert)
    privateKeySM := decodeSM2PrivateKey(signKey)

    content := []byte("hello world")

    tests := []struct{
        cert *cryptobin_x509.Certificate
        privkey crypto.PrivateKey
        dOid asn1.ObjectIdentifier
        eOid asn1.ObjectIdentifier
    }{
        {
            cert: cert,
            privkey: privateKey,
            dOid: OidDigestAlgorithmMD5,
            eOid: OidEncryptionAlgorithmRSAMD5,
        },
        {
            cert: cert,
            privkey: privateKey,
            dOid: OidDigestAlgorithmSHA1,
            eOid: OidEncryptionAlgorithmRSASHA1,
        },
        {
            cert: cert,
            privkey: privateKey,
            dOid: OidDigestAlgorithmSHA256,
            eOid: OidEncryptionAlgorithmRSASHA256,
        },
        {
            cert: cert,
            privkey: privateKey,
            dOid: OidDigestAlgorithmSHA512,
            eOid: OidEncryptionAlgorithmRSASHA512,
        },

        {
            cert: certSM,
            privkey: privateKeySM,
            dOid: OidDigestAlgorithmSM3,
            eOid: oidDigestEncryptionAlgorithmSM2,
        },
    }

    for i, test := range tests {
        t.Run(fmt.Sprintf("[%d] fail", i), func(t *testing.T) {
            pkcs7Sign, pkcs7err := signWithAlgorithm(
                content,
                test.cert,
                test.privkey,
                test.dOid,
                test.eOid,
            )

            assertError(pkcs7err, "Test_SignWithAlgorithm")
            assertNotEmpty(pkcs7Sign, "Test_SignWithAlgorithm")
        })
    }

}

func signWithAlgorithmWithSM2(
    content []byte,
    cert *cryptobin_x509.Certificate,
    privkey crypto.PrivateKey,
    dOid asn1.ObjectIdentifier,
    eOid asn1.ObjectIdentifier,
) (signed []byte, err error) {
    toBeSigned, err := NewSMSignedData(content)
    if err != nil {
        err = fmt.Errorf("Cannot initialize signed data: %s", err)
        return
    }

    toBeSigned.SetDigestAlgorithm(dOid)
    toBeSigned.SetEncryptionAlgorithm(eOid)

    if err = toBeSigned.AddSigner(cert, privkey, SignerInfoConfig{}); err != nil {
        err = fmt.Errorf("Cannot add signer: %s", err)
        return
    }

    // Detach signature, omit if you want an embedded signature
    toBeSigned.Detach()

    signed, err = toBeSigned.Finish()
    if err != nil {
        err = fmt.Errorf("Cannot finish signing data: %s", err)
        return
    }

    // Verify the signature
    // pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})

    p7, err := Parse(signed)
    if err != nil {
        err = fmt.Errorf("Cannot parse our signed data: %s", err)
        return
    }

    // since the signature was detached, reattach the content here
    p7.Content = content

    if bytes.Compare(content, p7.Content) != 0 {
        err = fmt.Errorf("Our content was not in the parsed data:\n\tExpected: %s\n\tActual: %s", content, p7.Content)
        return
    }
    if err = p7.Verify(); err != nil {
        err = fmt.Errorf("Cannot verify our signed data: %s", err)
        return
    }

    return
}

func Test_SignWithAlgorithmWithSM2(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    certSM := decodeCert(signCert)
    privateKeySM := decodeSM2PrivateKey(signKey)

    content := []byte("hello world")

    tests := []struct{
        cert *cryptobin_x509.Certificate
        privkey crypto.PrivateKey
        dOid asn1.ObjectIdentifier
        eOid asn1.ObjectIdentifier
    }{
        {
            cert: certSM,
            privkey: privateKeySM,
            dOid: OidDigestAlgorithmSM3,
            eOid: oidDigestEncryptionAlgorithmSM2,
        },
    }

    for i, test := range tests {
        t.Run(fmt.Sprintf("[%d] fail", i), func(t *testing.T) {
            pkcs7Sign, pkcs7err := signWithAlgorithmWithSM2(
                content,
                test.cert,
                test.privkey,
                test.dOid,
                test.eOid,
            )

            assertError(pkcs7err, "Test_SignWithAlgorithmWithSM2")
            assertNotEmpty(pkcs7Sign, "Test_SignWithAlgorithmWithSM2")
        })
    }

}

// =========

func Test_EncryptWithSM2(t *testing.T) {
    cert := decodeCert(encCert)
    privkey := decodeSM2PrivateKey(expectedEncKey)

    signed := []byte("test data test data test data test data")

    // 加密
    enData, err := Encrypt(rand.Reader, signed, []*cryptobin_x509.Certificate{
        cert,
    }, SM2Opts)
    if err != nil {
        t.Fatal(err)
    }

    enDataw := EncodePkcs7ToPem(enData, "ENCRYPTED PKCS7")

    // 解密
    deData, _ := ParsePkcs7Pem(enDataw)
    deDataw, err := Decrypt(deData, cert, privkey)
    if err != nil {
        t.Fatal(err)
    }

    if string(signed) != string(deDataw) {
        t.Errorf("Cannot Decrypt our signed data: %s", err)
    }
}

func Test_EncryptWithSM2_Check(t *testing.T) {
    cert := decodeCert(encCert)
    privkey := decodeSM2PrivateKey(expectedEncKey)

    signed := []byte("test data test data test data test data")

    enDataw := `-----BEGIN ENCRYPTED PKCS7-----
MIIBWQYKKoEcz1UGAQQCA6CCAUkwggFFAgEAMYHfMIHcAgEAME4wQjELMAkGA1UE
BhMCQ04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQK
DAjmtYvor5VDQQIIAs64zJDLT8UwCwYJKoEcz1UBgi0DBHoweAIgLUmEKmBUQ8eR
bWtayE/m+JZ33NHeN/LgBHg0AqpFIu0CIBa/qeTU1epKKN4RZkJKorbFnR7D+0pT
q36F/F+rbCqEBCBav2otgNKAxTb5/vd3PTZR+bvBeMf8vouhQqfgzf7WaAQQiB2k
Rl5Da50lhxhRXVJaIDBeBgoqgRzPVQYBBAIBMBwGCCqBHM9VAWgCBBD42vXIrcZv
HcSAHiSLOH+moDIEMJHOAAkMZX0mK2yMABW7uS28FImy+MCR88lXnsEFiUBxV6x1
PusUS6DMnQ9LYupDVQ==
-----END ENCRYPTED PKCS7-----`

    // 解密
    deData, _ := ParsePkcs7Pem([]byte(enDataw))
    deDataw, err := Decrypt(deData, cert, privkey)
    if err != nil {
        t.Fatal(err)
    }

    if string(signed) != string(deDataw) {
        t.Errorf("Cannot Decrypt our signed data: %s", err)
    }
}

func Test_EncryptUsingPSKWithSM2(t *testing.T) {
    key := []byte("123456789012werf")
    cipher := SM4CBC
    mode := SM2Mode
    signed := []byte("test data test data test data test data")

    // 加密
    enData, err := EncryptUsingPSK(rand.Reader, signed, key, cipher, mode)
    if err != nil {
        t.Fatal(err)
    }

    enDataw := EncodePkcs7ToPem(enData, "ENCRYPTED PKCS7")

    // 解密
    deData, _ := ParsePkcs7Pem(enDataw)
    deDataw, err := DecryptUsingPSK(deData, key)
    if err != nil {
        t.Fatal(err)
    }

    if string(signed) != string(deDataw) {
        t.Errorf("Cannot Decrypt our signed data: %s", err)
    }
}

func Test_EncryptUsingPSKWithSM2_Check(t *testing.T) {
    key := []byte("123456789012werf")
    signed := []byte("test data test data test data test data")

    enDataw := `-----BEGIN ENCRYPTED PKCS7-----
MHMGCiqBHM9VBgEEAgWgZTBjAgEAMF4GCiqBHM9VBgEEAgEwHAYIKoEcz1UBaAIE
EGu7Sm+oYi4II8z+w+6XRbygMgQwkeM2jorrym3zqbpMyOT/QK25sVB7HwouPq7a
vuk3jYCL5WnHOEwNVmIVn+ROgoMS
-----END ENCRYPTED PKCS7-----`

    // 解密
    deData, _ := ParsePkcs7Pem([]byte(enDataw))
    deDataw, err := DecryptUsingPSK(deData, key)
    if err != nil {
        t.Fatal(err)
    }

    if string(signed) != string(deDataw) {
        t.Errorf("Cannot Decrypt our signed data: %s", err)
    }
}

// ===========

// echo -n "This is a test" > test.txt
// openssl cms -encrypt -in test.txt cert.pem
var EncryptedTestFixture = `
-----BEGIN PKCS7-----
MIIBGgYJKoZIhvcNAQcDoIIBCzCCAQcCAQAxgcwwgckCAQAwMjApMRAwDgYDVQQK
EwdBY21lIENvMRUwEwYDVQQDEwxFZGRhcmQgU3RhcmsCBQDL+CvWMA0GCSqGSIb3
DQEBAQUABIGAyFz7bfI2noUs4FpmYfztm1pVjGyB00p9x0H3gGHEYNXdqlq8VG8d
iq36poWtEkatnwsOlURWZYECSi0g5IAL0U9sj82EN0xssZNaK0S5FTGnB3DPvYgt
HJvcKq7YvNLKMh4oqd17C6GB4oXyEBDj0vZnL7SUoCAOAWELPeC8CTUwMwYJKoZI
hvcNAQcBMBQGCCqGSIb3DQMHBAhEowTkot3a7oAQFD//J/IhFnk+JbkH7HZQFA==
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIB1jCCAUGgAwIBAgIFAMv4K9YwCwYJKoZIhvcNAQELMCkxEDAOBgNVBAoTB0Fj
bWUgQ28xFTATBgNVBAMTDEVkZGFyZCBTdGFyazAeFw0xNTA1MDYwMzU2NDBaFw0x
NjA1MDYwMzU2NDBaMCUxEDAOBgNVBAoTB0FjbWUgQ28xETAPBgNVBAMTCEpvbiBT
bm93MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDK6NU0R0eiCYVquU4RcjKc
LzGfx0aa1lMr2TnLQUSeLFZHFxsyyMXXuMPig3HK4A7SGFHupO+/1H/sL4xpH5zg
8+Zg2r8xnnney7abxcuv0uATWSIeKlNnb1ZO1BAxFnESc3GtyOCr2dUwZHX5mRVP
+Zxp2ni5qHNraf3wE2VPIQIDAQABoxIwEDAOBgNVHQ8BAf8EBAMCAKAwCwYJKoZI
hvcNAQELA4GBAIr2F7wsqmEU/J/kLyrCgEVXgaV/sKZq4pPNnzS0tBYk8fkV3V18
sBJyHKRLL/wFZASvzDcVGCplXyMdAOCyfd8jO3F9Ac/xdlz10RrHJT75hNu3a7/n
9KNwKhfN4A1CQv2x372oGjRhCW5bHNCWx4PIVeNzCyq/KZhyY9sxHE6f
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIICXgIBAAKBgQDK6NU0R0eiCYVquU4RcjKcLzGfx0aa1lMr2TnLQUSeLFZHFxsy
yMXXuMPig3HK4A7SGFHupO+/1H/sL4xpH5zg8+Zg2r8xnnney7abxcuv0uATWSIe
KlNnb1ZO1BAxFnESc3GtyOCr2dUwZHX5mRVP+Zxp2ni5qHNraf3wE2VPIQIDAQAB
AoGBALyvnSt7KUquDen7nXQtvJBudnf9KFPt//OjkdHHxNZNpoF/JCSqfQeoYkeu
MdAVYNLQGMiRifzZz4dDhA9xfUAuy7lcGQcMCxEQ1dwwuFaYkawbS0Tvy2PFlq2d
H5/HeDXU4EDJ3BZg0eYj2Bnkt1sJI35UKQSxblQ0MY2q0uFBAkEA5MMOogkgUx1C
67S1tFqMUSM8D0mZB0O5vOJZC5Gtt2Urju6vywge2ArExWRXlM2qGl8afFy2SgSv
Xk5eybcEiQJBAOMRwwbEoW5NYHuFFbSJyWll4n71CYuWuQOCzehDPyTb80WFZGLV
i91kFIjeERyq88eDE5xVB3ZuRiXqaShO/9kCQQCKOEkpInaDgZSjskZvuJ47kByD
6CYsO4GIXQMMeHML8ncFH7bb6AYq5ybJVb2NTU7QLFJmfeYuhvIm+xdOreRxAkEA
o5FC5Jg2FUfFzZSDmyZ6IONUsdF/i78KDV5nRv1R+hI6/oRlWNCtTNBv/lvBBd6b
dseUE9QoaQZsn5lpILEvmQJAZ0B+Or1rAYjnbjnUhdVZoy9kC4Zov+4UH3N/BtSy
KJRWUR0wTWfZBPZ5hAYZjTBEAFULaYCXlQKsODSp0M1aQA==
-----END PRIVATE KEY-----`

func Test_Decrypt_Check(t *testing.T) {
    fixture := unmarshalTestFixture(EncryptedTestFixture)

    content, err := Decrypt(fixture.Input, fixture.Certificate, fixture.PrivateKey)
    if err != nil {
        t.Errorf("Cannot Decrypt with error: %v", err)
    }

    expected := []byte("This is a test")
    if !bytes.Equal(content, expected) {
        t.Errorf("Decrypted result does not match.\n\tExpected:%s\n\tActual:%s", expected, content)
    }
}
