package pkcs12

import (
    "time"
    "testing"
    "math/big"
    "crypto/rsa"
    "crypto/sha1"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/hex"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs8/pbes1"
    "github.com/deatil/go-cryptobin/pkcs12/enveloped"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var testP12Key = `
-----BEGIN Data-----
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
-----END Data-----
`

func Test_P12_Decode(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    pfxData := decodePEM(testP12Key)

    password := "notasecret"

    p12, err := LoadPKCS12FromBytes(pfxData, password)
    assertError(err, "P12Decode-pfxData")

    if err == nil {
        prikey, attrs, _ := p12.GetPrivateKey()
        assertNotEmpty(prikey, "P12Decode-prikey")
        assertNotEmpty(attrs, "P12Decode-attrs")

        cert, certAttrs, _ := p12.GetCert()
        assertNotEmpty(cert, "P12Decode-cert")
        assertNotEmpty(certAttrs, "P12Decode-certAttrs")

        // t.Errorf("%v", attrs.ToArray())
        // t.Errorf("%v", certAttrs.ToArray())
    }
}

func Test_P12_EncodeChain(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    caCerts, err := x509.ParseCertificates(decodePEM(caCert))
    assertError(err, "P12_EncodeChain-caCerts")

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "P12_EncodeChain-certificates")

    parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
    assertError(err, "P12_EncodeChain-privateKey")

    privateKey, ok := parsedKey.(*rsa.PrivateKey)
    if !ok {
        t.Error("P12_EncodeChain rsa Error")
    }

    password := "password-testkjjj"

    p12 := NewPKCS12Encode()
    p12.AddPrivateKey(privateKey)
    p12.AddCert(certificates[0])
    p12.AddCaCerts(caCerts)

    pfxData, err := p12.Marshal(rand.Reader, password, Opts{
        KeyCipher: GetPbes1CipherFromName("SHA1AndRC2_40"),
        CertCipher: CipherSHA1AndRC2_40,
        MacKDFOpts: MacOpts{
            SaltSize: 8,
            IterationCount: 1,
            HMACHash: SHA1,
        },
    })

    assertError(err, "P12_EncodeChain-pfxData")
    assertNotEmpty(pfxData, "P12_EncodeChain-pfxData")

    pp12, err := LoadPKCS12FromBytes(pfxData, password)
    assertError(err, "P12Decode-pfxData")

    privateKey2, attrs, _ := pp12.GetPrivateKey()
    assertNotEmpty(privateKey2, "P12Decode-prikey")
    assertNotEmpty(attrs, "P12Decode-attrs")
    assertEqual(privateKey2, privateKey, "P12_EncodeChain-privateKey2")

    certificate2, certAttrs, _ := pp12.GetCert()
    assertNotEmpty(certificate2, "P12Decode-cert")
    assertNotEmpty(certAttrs, "P12Decode-certAttrs")
    assertEqual(certificate2, certificates[0], "P12_EncodeChain-certificate2")

    caCerts2, _ := pp12.GetCaCerts()
    assertNotEmpty(caCerts2, "P12Decode-caCerts2")
    assertEqual(caCerts2, caCerts, "P12_EncodeChain-caCerts2")
}

func Test_P12_EncodeSecret(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertNotBool := cryptobin_test.AssertNotBoolT(t)

    secretKey := []byte("test-password")
    password := "passpass word"

    p12 := NewPKCS12Encode()
    p12.AddSecretKey(secretKey)

    pfxData, err := p12.Marshal(rand.Reader, password, DefaultOpts)
    assertError(err, "P12_EncodeSecret")

    pp12, err := LoadPKCS12FromBytes(pfxData, password)
    assertError(err, "P12_EncodeSecret-pfxData")

    secretKey2, attrs, _ := pp12.GetSecretKey()
    assertNotEmpty(secretKey2, "P12_EncodeSecret-secretKey2")
    assertNotEmpty(attrs, "P12_EncodeSecret-secretKey2-attrs")
    assertEqual(secretKey2, secretKey, "P12_EncodeSecret-secretKey2")

    oldpass2 := sha1.Sum(secretKey)
    newpass2 := attrs.ToArray()

    assertEqual(newpass2["localKeyId"], hex.EncodeToString(oldpass2[:]), "secretKey")
    assertEqual(attrs.GetAttr("localKeyId"), hex.EncodeToString(oldpass2[:]), "secretKey")

    assertBool(attrs.HasAttr("localKeyId"), "P12_EncodeSecret-HasAttr")
    assertNotBool(attrs.HasAttr("localKeyId22222"), "P12_EncodeSecret-HasAttr")

    assertNotBool(pp12.HasPrivateKey(), "P12_EncodeSecret-HasPrivateKey")
    assertNotBool(pp12.HasCert(), "P12_EncodeSecret-HasCert")
    assertNotBool(pp12.HasCaCert(), "P12_EncodeSecret-HasCaCert")
    assertNotBool(pp12.HasTrustStore(), "P12_EncodeSecret-HasTrustStore")

    assertBool(pp12.HasSecretKey(), "P12_EncodeSecret-HasSecretKey")
}

func Test_P12_EncodeTrustStore(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "P12_EncodeTrustStore-certificates")

    password := "password-testkjjj"

    p12 := NewPKCS12Encode()
    p12.AddTrustStores(certificates)

    pfxData, err := p12.Marshal(rand.Reader, password, Opts{
        KeyCipher: GetPbes1CipherFromName("SHA1AndRC2_40"),
        CertCipher: CipherSHA1AndRC2_40,
        MacKDFOpts: MacOpts{
            SaltSize: 8,
            IterationCount: 1,
            HMACHash: SHA1,
        },
    })
    assertError(err, "P12_EncodeTrustStore-pfxData")

    assertNotEmpty(pfxData, "P12_EncodeTrustStore-pfxData")

    // 新版本
    pp12, err := LoadPKCS12FromBytes(pfxData, password)
    assertError(err, "P12_EncodeTrustStore-pfxData")

    certificates2, _ := pp12.GetTrustStores()
    assertNotEmpty(certificates2, "P12_EncodeTrustStore-certificates2")
    assertEqual(certificates2, certificates, "P12_EncodeTrustStore-certificates2")
}

func Test_P12_EncodeTrustStoreEntries(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "P12_EncodeTrustStoreEntries-certificates")

    password := "password-testkjjj"

    entries := make([]TrustStoreData, 0)
    entries = append(entries, NewTrustStoreData(certificates[0], "FriendlyName-Test"))

    p12 := NewPKCS12Encode()
    p12.AddTrustStoreEntries(entries)

    pfxData, err := p12.Marshal(rand.Reader, password, Opts{
        KeyCipher: GetPbes1CipherFromName("SHA1AndRC2_40"),
        CertCipher: CipherSHA1AndRC2_40,
        MacKDFOpts: MacOpts{
            SaltSize: 8,
            IterationCount: 1,
            HMACHash: SHA1,
        },
    })

    assertError(err, "P12_EncodeTrustStoreEntries-pfxData")

    assertNotEmpty(pfxData, "P12_EncodeTrustStoreEntries-pfxData")

    // 新版本
    pp12, err := LoadPKCS12FromBytes(pfxData, password)
    assertError(err, "P12_EncodeTrustStoreEntries-pfxData")

    certificates2, _ := pp12.GetTrustStoreEntries()
    assertNotEmpty(certificates2, "P12_EncodeTrustStoreEntries")

    attrs2 := certificates2[0].Attrs.ToArray()

    assertEqual(certificates2[0].Cert, certificates[0], "P12_EncodeTrustStoreEntries-certificate2")

    assertEqual(attrs2["friendlyName"], "FriendlyName-Test", "P12_EncodeTrustStoreEntries-friendlyName")
    assertEqual(attrs2["javaTrustStore"], "2.5.29.37.0", "P12_EncodeTrustStoreEntries-friendlyName")
}

func Test_P12_EncodePbes2_Check(t *testing.T) {
    t.Run("EncodePbes2_Check", func(t *testing.T) {
        assertEqual := cryptobin_test.AssertEqualT(t)
        assertError := cryptobin_test.AssertErrorT(t)

        certificates, err := x509.ParseCertificates(decodePEM(certificate))
        assertError(err, "P12_EncodePbes2_Check-certificates")

        parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
        assertError(err, "P12_EncodePbes2_Check-privateKey")

        privateKey, ok := parsedKey.(*rsa.PrivateKey)
        if !ok {
            t.Error("P12_EncodePbes2_Check rsa Error")
        }

        pfxData := decodePEM(testNewPfxPbes2_Encode)

        password := "pass"

        pp12, err := LoadPKCS12FromBytes(pfxData, password)
        assertError(err, "P12_EncodePbes2_Check-pfxData")

        privateKey2, _, _ := pp12.GetPrivateKey()
        certificate2, _, _ := pp12.GetCert()

        assertEqual(privateKey2, privateKey, "P12_EncodePbes2_Check-privateKey2")
        assertEqual(certificate2, certificates[0], "P12_EncodePbes2_Check-certificate2")
    })
}

func Test_P12_EncodeChain_Check(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    caCerts, err := x509.ParseCertificates(decodePEM(caCert))
    assertError(err, "P12_EncodeChain_Check-caCerts")

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "P12_EncodeChain_Check-certificates")

    parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
    assertError(err, "P12_EncodeChain_Check-privateKey")

    privateKey, ok := parsedKey.(*rsa.PrivateKey)
    if !ok {
        t.Error("P12_EncodeChain_Check rsa Error")
    }

    pfxData := decodePEM(testNewPfxCa_Encode)

    password := "pass"

    pp12, err := LoadPKCS12FromBytes(pfxData, password)
    assertError(err, "P12_EncodeChain_Check-pfxData")

    privateKey2, _, _ := pp12.GetPrivateKey()
    certificate2, _, _ := pp12.GetCert()
    caCerts2, _ := pp12.GetCaCerts()

    assertEqual(privateKey2, privateKey, "P12_EncodeChain_Check-privateKey2")
    assertEqual(certificate2, certificates[0], "P12_EncodeChain_Check-certificate2")
    assertEqual(caCerts2, caCerts, "P12_EncodeChain_Check-caCerts2")
}

func Test_P12_Encode(t *testing.T) {
    test_P12_Encode(t, testOpt, "password-testkjjj", "P12_testOpt")
    test_P12_Encode(t, LegacyRC2Opts, "password-testkjjj", "P12_LegacyRC2Opts")
    test_P12_Encode(t, LegacyDESOpts, "password-testkjjj", "P12_LegacyDESOpts")
    test_P12_Encode(t, Modern2023Opts, "passwordpasswordpasswordpassword", "P12_Modern2023Opts")
}

func test_P12_Encode(t *testing.T, opts Opts, password string, name string) {
    t.Run(name, func(t *testing.T) {
        assertEqual := cryptobin_test.AssertEqualT(t)
        assertError := cryptobin_test.AssertErrorT(t)
        assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
        assertBool := cryptobin_test.AssertBoolT(t)
        assertNotBool := cryptobin_test.AssertNotBoolT(t)

        certificates, err := x509.ParseCertificates(decodePEM(certificate))
        assertError(err, "P12_Encode-certificates")

        parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
        assertError(err, "P12_Encode-privateKey")

        privateKey, ok := parsedKey.(*rsa.PrivateKey)
        if !ok {
            t.Error("P12_Encode rsa Error")
        }

        p12 := NewPKCS12Encode()
        p12.AddPrivateKey(privateKey)
        p12.AddCert(certificates[0])

        pfxData, err := p12.Marshal(rand.Reader, password, opts)
        assertError(err, "P12_Encode-pfxData")

        assertNotEmpty(pfxData, "P12_Encode-pfxData")

        // 解析
        pp12, err := LoadPKCS12FromBytes(pfxData, password)
        assertError(err, "P12Decode-pfxData")

        privateKey2, _, _ := pp12.GetPrivateKey()
        certificate2, _, _ := pp12.GetCert()

        assertEqual(privateKey2, privateKey, "P12_Decode-privateKey2")
        assertEqual(certificate2, certificates[0], "P12_Decode-certificate2")

        assertBool(pp12.HasPrivateKey(), "P12_SM2Pkcs12_Decode-HasPrivateKey")
        assertBool(pp12.HasCert(), "P12_SM2Pkcs12_Decode-HasCert")

        assertNotBool(pp12.HasCaCert(), "P12_SM2Pkcs12_Decode-HasCaCert")
        assertNotBool(pp12.HasTrustStore(), "P12_SM2Pkcs12_Decode-HasTrustStore")
        assertNotBool(pp12.HasSecretKey(), "P12_SM2Pkcs12_Decode-HasSecretKey")
    })
}

func Test_P12_ToPem(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    pfxData := decodePEM(testP12Key)

    password := "notasecret"

    p12, err := LoadPKCS12FromBytes(pfxData, password)
    assertError(err, "P12_ToPem-pfxData")

    blocks, err := p12.ToPEM()
    assertError(err, "P12_ToPem-ToPEM")
    assertNotEmpty(blocks, "P12_ToPem-ToPEM")

    var pemData [][]byte
    for _, b := range blocks {
        pemData = append(pemData, pem.EncodeToMemory(b))
    }

    for _, pemInfo := range pemData {
        assertNotEmpty(pemInfo, "P12_ToPem-ToPEM-Pem")
    }
}

func Test_P12_ToOriginalPEM(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    pfxData := decodePEM(testP12Key)

    password := "notasecret"

    p12, err := LoadPKCS12FromBytes(pfxData, password)
    assertError(err, "Test_P12_ToOriginalPEM-pfxData")

    blocks, err := p12.ToOriginalPEM()
    assertError(err, "Test_P12_ToOriginalPEM-ToPEM")
    assertNotEmpty(blocks, "Test_P12_ToOriginalPEM-ToPEM")

    var pemData [][]byte
    for _, b := range blocks {
        pemData = append(pemData, pem.EncodeToMemory(b))
    }

    for _, pemInfo := range pemData {
        assertNotEmpty(pemInfo, "Test_P12_ToOriginalPEM-ToPEM-Pem")
        // t.Error(string(pemInfo))
    }
}

// 某些库生成的 SHA1 值可能不对，不能完全的作为判断
func Test_P12_Attrs_Verify(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)

    pfxData := decodePEM(testNewPfx_Encode)

    password := "pass"

    p12, err := LoadPKCS12FromBytes(pfxData, password)
    assertError(err, "P12_Attrs_Verify-pfxData")

    privateKey2, priAttrs, _ := p12.GetPrivateKey()

    assertNotEmpty(privateKey2, "P12_Attrs_Verify-privateKey2")
    assertNotEmpty(priAttrs, "P12_Attrs_Verify-priAttrs")

    certificate2, certAttrs, _ := p12.GetCert()

    assertNotEmpty(certificate2, "P12_Attrs_Verify-certificate2")
    assertNotEmpty(certAttrs, "P12_Attrs_Verify-certAttrs")

    priCheck := priAttrs.Verify(certificate2.Raw)
    assertBool(priCheck, "P12_Attrs_Verify-priCheck")
}

// 自定义 LocalKeyId
func Test_P12_EncodeSecret_SetLocalKeyId(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertNotBool := cryptobin_test.AssertNotBoolT(t)

    secretKey := []byte("test-password")
    password := "passpass word"

    localKeyId := []byte("aaaaaaahhhhh")
    localKeyIdHex := hex.EncodeToString(localKeyId)

    p12 := NewPKCS12Encode()
    p12.AddSecretKey(secretKey)
    p12.WithLocalKeyId(localKeyId)

    pfxData, err := p12.Marshal(rand.Reader, password, DefaultOpts)
    assertError(err, "P12_EncodeSecret")

    // 解析
    pp12, err := LoadPKCS12FromBytes(pfxData, password)
    assertError(err, "P12_EncodeSecret_SetLocalKeyId-pfxData")

    secretKey2, attrs, _ := pp12.GetSecretKey()
    assertNotEmpty(secretKey2, "P12_EncodeSecret_SetLocalKeyId-secretKey2")
    assertNotEmpty(attrs, "P12_EncodeSecret_SetLocalKeyId-secretKey2-attrs")
    assertEqual(secretKey2, secretKey, "P12_EncodeSecret_SetLocalKeyId-secretKey2")

    newpass2 := attrs.ToArray()

    assertEqual(newpass2["localKeyId"], localKeyIdHex, "P12_EncodeSecret_SetLocalKeyId-localKeyId")

    assertNotBool(pp12.HasPrivateKey(), "P12_EncodeSecret_SetLocalKeyId-HasPrivateKey")
    assertNotBool(pp12.HasCert(), "P12_EncodeSecret_SetLocalKeyId-HasCert")
    assertNotBool(pp12.HasCaCert(), "P12_EncodeSecret_SetLocalKeyId-HasCaCert")
    assertNotBool(pp12.HasTrustStore(), "P12_EncodeSecret_SetLocalKeyId-HasTrustStore")

    assertBool(pp12.HasSecretKey(), "P12_EncodeSecret_SetLocalKeyId-HasSecretKey")
}

func Test_P12_EncodeSdsiCert(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    sdsiCert := []byte("sdsiCert-data")
    password := "passpass word"

    p12 := NewPKCS12Encode()
    p12.AddSdsiCertBytes(sdsiCert)

    pfxData, err := p12.Marshal(rand.Reader, password, DefaultOpts)
    assertError(err, "P12_EncodeSdsiCert")

    pp12, err := LoadPKCS12FromBytes(pfxData, password)
    assertError(err, "P12_EncodeSdsiCert-pfxData")

    sdsiCert2, attrs, _ := pp12.GetSdsiCertBytes()
    assertNotEmpty(sdsiCert2, "P12_EncodeSdsiCert-sdsiCert2")
    assertNotEmpty(attrs, "P12_EncodeSdsiCert-sdsiCert2-attrs")
    assertEqual(sdsiCert2, sdsiCert, "P12_EncodeSdsiCert-sdsiCert2")

    oldpass2 := sha1.Sum(sdsiCert)
    newpass2 := attrs.ToArray()

    assertEqual(newpass2["localKeyId"], hex.EncodeToString(oldpass2[:]), "secretKey")
}

func Test_P12_EncodeCRL(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    crlBytes := []byte("crlBytes-data")
    password := "passpass word"

    p12 := NewPKCS12Encode()
    p12.AddCRLBytes(crlBytes)

    pfxData, err := p12.Marshal(rand.Reader, password, DefaultOpts)
    assertError(err, "P12_EncodeSdsiCert")

    pp12, err := LoadPKCS12FromBytes(pfxData, password)
    assertError(err, "P12_EncodeSdsiCert-pfxData")

    crlBytes2, attrs, _ := pp12.GetCRLBytes()
    assertNotEmpty(crlBytes2, "P12_EncodeSdsiCert-crlBytes2")
    assertNotEmpty(attrs, "P12_EncodeSdsiCert-crlBytes2-attrs")
    assertEqual(crlBytes2, crlBytes, "P12_EncodeSdsiCert-crlBytes2")

    oldpass2 := sha1.Sum(crlBytes)
    newpass2 := attrs.ToArray()

    assertEqual(newpass2["localKeyId"], hex.EncodeToString(oldpass2[:]), "secretKey")
}

var pemPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCxoeCUW5KJxNPxMp+KmCxKLc1Zv9Ny+4CFqcUXVUYH69L3mQ7v
IWrJ9GBfcaA7BPQqUlWxWM+OCEQZH1EZNIuqRMNQVuIGCbz5UQ8w6tS0gcgdeGX7
J7jgCQ4RK3F/PuCM38QBLaHx988qG8NMc6VKErBjctCXFHQt14lerd5KpQIDAQAB
AoGAYrf6Hbk+mT5AI33k2Jt1kcweodBP7UkExkPxeuQzRVe0KVJw0EkcFhywKpr1
V5eLMrILWcJnpyHE5slWwtFHBG6a5fLaNtsBBtcAIfqTQ0Vfj5c6SzVaJv0Z5rOd
7gQF6isy3t3w9IF3We9wXQKzT6q5ypPGdm6fciKQ8RnzREkCQQDZwppKATqQ41/R
vhSj90fFifrGE6aVKC1hgSpxGQa4oIdsYYHwMzyhBmWW9Xv/R+fPyr8ZwPxp2c12
33QwOLPLAkEA0NNUb+z4ebVVHyvSwF5jhfJxigim+s49KuzJ1+A2RaSApGyBZiwS
rWvWkB471POAKUYt5ykIWVZ83zcceQiNTwJBAMJUFQZX5GDqWFc/zwGoKkeR49Yi
MTXIvf7Wmv6E++eFcnT461FlGAUHRV+bQQXGsItR/opIG7mGogIkVXa3E1MCQARX
AAA7eoZ9AEHflUeuLn9QJI/r0hyQQLEtrpwv6rDT1GCWaLII5HJ6NUFVf4TTcqxo
6vdM4QGKTJoO+SaCyP0CQFdpcxSAuzpFcKv0IlJ8XzS/cy+mweCMwyJ1PFEc4FX6
wg/HcAJWY60xZTJDFN+Qfx8ZQvBEin6c2/h+zZi5IVY=
-----END RSA PRIVATE KEY-----
`
const pemCertificate = `-----BEGIN CERTIFICATE-----
MIIDATCCAemgAwIBAgIRAKQkkrFx1T/dgB/Go/xBM5swDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xNjA4MTcyMDM2MDdaFw0xNzA4MTcyMDM2
MDdaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDAoJtjG7M6InsWwIo+l3qq9u+g2rKFXNu9/mZ24XQ8XhV6PUR+5HQ4
jUFWC58ExYhottqK5zQtKGkw5NuhjowFUgWB/VlNGAUBHtJcWR/062wYrHBYRxJH
qVXOpYKbIWwFKoXu3hcpg/CkdOlDWGKoZKBCwQwUBhWE7MDhpVdQ+ZljUJWL+FlK
yQK5iRsJd5TGJ6VUzLzdT4fmN2DzeK6GLeyMpVpU3sWV90JJbxWQ4YrzkKzYhMmB
EcpXTG2wm+ujiHU/k2p8zlf8Sm7VBM/scmnMFt0ynNXop4FWvJzEm1G0xD2t+e2I
5Utr04dOZPCgkm++QJgYhtZvgW7ZZiGTAgMBAAGjUjBQMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMBsGA1UdEQQUMBKC
EHRlc3QuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEBADpqKQxrthH5InC7
X96UP0OJCu/lLEMkrjoEWYIQaFl7uLPxKH5AmQPH4lYwF7u7gksR7owVG9QU9fs6
1fK7II9CVgCd/4tZ0zm98FmU4D0lHGtPARrrzoZaqVZcAvRnFTlPX5pFkPhVjjai
/mkxX9LpD8oK1445DFHxK5UjLMmPIIWd8EOi+v5a+hgGwnJpoW7hntSl8kHMtTmy
fnnktsblSUV4lRCit0ymC7Ojhe+gzCCwkgs5kDzVVag+tnl/0e2DloIjASwOhpbH
KVcg7fBd484ht/sS+l0dsB4KDOSpd8JzVDMF8OZqlaydizoJO0yWr9GbCN1+OKq5
EhLrEqU=
-----END CERTIFICATE-----`

func Test_P12_EncodeCRL_OBJ(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    crlBytes := []byte("crlBytes-data")
    password := "passpass word"

    block, _ := pem.Decode([]byte(pemPrivateKey))
    privRSA, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
    block, _ = pem.Decode([]byte(pemCertificate))
    certRSA, _ := x509.ParseCertificate(block.Bytes)

    loc := time.FixedZone("Oz/Atlantis", int((2 * time.Hour).Seconds()))

    now := time.Unix(1000, 0).In(loc)
    nowUTC := now.UTC()
    expiry := time.Unix(10000, 0)

    revokedCerts := []pkix.RevokedCertificate{
        {
            SerialNumber:   big.NewInt(1),
            RevocationTime: nowUTC,
        },
        {
            SerialNumber: big.NewInt(42),
            // RevocationTime should be converted to UTC before marshaling.
            RevocationTime: now,
        },
    }
    expectedCerts := []pkix.RevokedCertificate{
        {
            SerialNumber:   big.NewInt(1),
            RevocationTime: nowUTC,
        },
        {
            SerialNumber:   big.NewInt(42),
            RevocationTime: nowUTC,
        },
    }

    crlBytes, err := certRSA.CreateCRL(rand.Reader, privRSA, revokedCerts, now, expiry)
    assertError(err, "P12_EncodeCRL_OBJ-CreateCRL")

    parsedCRL, err := x509.ParseDERCRL(crlBytes)
    assertError(err, "P12_EncodeCRL_OBJ-parsedCRL")

    p12 := NewPKCS12Encode()
    p12.AddCRL(parsedCRL)

    pfxData, err := p12.Marshal(rand.Reader, password, DefaultOpts)
    assertError(err, "P12_EncodeCRL_OBJ")

    pp12, err := LoadPKCS12FromBytes(pfxData, password)
    assertError(err, "P12_EncodeCRL_OBJ-pfxData")

    crlBytes2, attrs, _ := pp12.GetCRLBytes()
    assertNotEmpty(crlBytes2, "P12_EncodeCRL_OBJ-crlBytes2")
    assertNotEmpty(attrs, "P12_EncodeCRL_OBJ-crlBytes2-attrs")
    assertEqual(crlBytes2, crlBytes, "P12_EncodeCRL_OBJ-crlBytes2")

    parsedCRL2, err := x509.ParseDERCRL(crlBytes2)
    assertError(err, "P12_EncodeCRL_OBJ-parsedCRL2")
    assertNotEmpty(parsedCRL2, "P12_EncodeCRL_OBJ-parsedCRL2")
    assertEqual(parsedCRL2.TBSCertList.RevokedCertificates, expectedCerts, "P12_EncodeCRL_OBJ-parsedCRL2")

    oldpass2 := sha1.Sum(crlBytes)
    newpass2 := attrs.ToArray()

    assertEqual(newpass2["localKeyId"], hex.EncodeToString(oldpass2[:]), "secretKey")
}

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

func Test_P12_Enveloped_Encode(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "P12_Enveloped_Encode-certificates")

    parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
    assertError(err, "P12_Enveloped_Encode-privateKey")

    privateKey, ok := parsedKey.(*rsa.PrivateKey)
    if !ok {
        t.Error("P12_Enveloped_Encode rsa Error")
    }

    password := "password-testkjjj"
    opts := Opts{
        KeyCipher:  pbes1.SHA1And3DES,
        CertCipher: EnvelopedCipher,
        MacKDFOpts: MacOpts{
            SaltSize: 8,
            IterationCount: 1,
            HMACHash: SHA1,
        },
    }

    derBlock1, _ := pem.Decode([]byte(testEncryptedTestCertificate))
    derBlock2, _ := pem.Decode([]byte(testEncryptedTestPrivateKey))

    cert1, _ := x509.ParseCertificate(derBlock1.Bytes)
    parsedKey1, _ := x509.ParsePKCS8PrivateKey(derBlock2.Bytes)
    privKey, _ := parsedKey1.(*rsa.PrivateKey)

    envelopedOpts := EnvelopedOpts{
        Cipher: enveloped.AES256CBC,
        KeyEncrypt: enveloped.KeyEncryptRSA,
        Recipients: []*x509.Certificate{cert1},
    }

    p12 := NewPKCS12Encode()
    p12.AddPrivateKey(privateKey)
    p12.AddCert(certificates[0])
    p12.WithEnvelopedOpts(envelopedOpts)

    pfxData, err := p12.Marshal(rand.Reader, password, opts)
    assertError(err, "P12_Enveloped_Encode-pfxData")

    assertNotEmpty(pfxData, "P12_Enveloped_Encode-pfxData")

    // 解析
    envelopedOpts2 := EnvelopedOpts{
        Cert: cert1,
        PrivateKey: privKey,
    }

    pp12 := NewPKCS12()
    pp12.WithEnvelopedOpts(envelopedOpts2)
    pp12, err = pp12.Parse(pfxData, password)
    assertError(err, "P12_Enveloped_Encode-pfxData")

    privateKey2, _, _ := pp12.GetPrivateKey()
    certificate2, _, _ := pp12.GetCert()

    assertEqual(privateKey2, privateKey, "P12_Enveloped_Encode-privateKey2")
    assertEqual(certificate2, certificates[0], "P12_Enveloped_Encode-certificate2")
}

var testEnvelopedP12Pem = `-----BEGIN CERTIFICATE-----
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
5b4Fkc9ZHFGoK6yNNQW1dBAjjrxGuXhidfw==
-----END CERTIFICATE-----`

func Test_P12_Enveloped_Check(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "P12_Enveloped_Check-certificates")

    parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
    assertError(err, "P12_Enveloped_Check-privateKey")

    privateKey, ok := parsedKey.(*rsa.PrivateKey)
    if !ok {
        t.Error("P12_Enveloped_Check rsa Error")
    }

    password := "password-testkjjj"
    pfxData := decodePEM(testEnvelopedP12Pem)

    derBlock1, _ := pem.Decode([]byte(testEncryptedTestCertificate))
    derBlock2, _ := pem.Decode([]byte(testEncryptedTestPrivateKey))

    cert1, _ := x509.ParseCertificate(derBlock1.Bytes)
    privKey, _ := x509.ParsePKCS8PrivateKey(derBlock2.Bytes)

    // 解析
    envelopedOpts := EnvelopedOpts{
        Cert: cert1,
        PrivateKey: privKey,
    }

    pp12 := NewPKCS12()
    pp12.WithEnvelopedOpts(envelopedOpts)
    pp12, err = pp12.Parse(pfxData, password)
    assertError(err, "P12_Enveloped_Check-pfxData")

    privateKey2, _, _ := pp12.GetPrivateKey()
    certificate2, _, _ := pp12.GetCert()

    assertEqual(privateKey2, privateKey, "P12_Enveloped_Check-privateKey2")
    assertEqual(certificate2, certificates[0], "P12_Enveloped_Check-certificate2")
}

var testUnknowP12Pem = `-----BEGIN CERTIFICATE-----
MIH6AgEDMIHFBgkqhkiG9w0BBwGggbcEgbQwgbEwga4GCSqGSIb3DQEHBqC
BoDCBnQIBADCBlwYJKoZIhvcNAQcBMCgGCiqGSIb3DQEMAQYwGgQU/YpCt9kpY8/1qIuCRvkq3Dt6TII
CAggAgGASH1n+TRDvsr4KWH04sn57+C6QEcHegUHihcZLXiJmjKuyTbmqGQ5TbB67uwQr6lPzIj7bAe6
uDhsyootKEcJwJK2kl9fiv57aDAMKdb05+HVYXFoLSAAqr0hwAl8+YRcwLTAhMAkGBSsOAwIaBQAEFO+
PqfooLirjlapSJekxacudIazDBAhNN4STa9QHCA==
-----END CERTIFICATE-----`

func Test_P12_UnknowOid_Check(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    pfxData := decodePEM(testUnknowP12Pem)

    password := "passpass word"

    p12, err := LoadPKCS12FromBytes(pfxData, password)
    assertError(err, "P12_UnknowOid_Check-pfxData")

    unknows, err := p12.GetUnknowsBytes()
    assertError(err, "P12_UnknowOid_Check-GetUnknowsBytes")
    assertNotEmpty(unknows, "P12_UnknowOid_Check-GetUnknowsBytes")

    for _, unknow := range unknows{
        assertNotEmpty(unknow.Data, "P12_UnknowOid_Check-Data")
        assertNotEmpty(unknow.Attrs.ToArray(), "P12_UnknowOid_Check-Attrs")
    }
}

func Test_P12_Attrs_Names(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    pfxData := decodePEM(testNewPfx_Encode)

    password := "pass"

    p12, err := LoadPKCS12FromBytes(pfxData, password)
    assertError(err, "P12_Attrs_Names-pfxData")

    privateKey2, priAttrs, _ := p12.GetPrivateKey()

    assertNotEmpty(privateKey2, "P12_Attrs_Names-privateKey2")
    assertNotEmpty(priAttrs, "P12_Attrs_Names-priAttrs")

    prinames := priAttrs.Names()
    assertNotEmpty(prinames, "P12_Attrs_Names-priNames")

    certPriNames := []string{"localKeyId"}
    assertEqual(prinames, certPriNames, "P12_Attrs_Names-certPriNames-Equal")

    certificate2, certAttrs, _ := p12.GetCert()

    assertNotEmpty(certificate2, "P12_Attrs_Names-certificate2")
    assertNotEmpty(certAttrs, "P12_Attrs_Names-certAttrs")

    certnames := certAttrs.Names()
    assertNotEmpty(certnames, "P12_Attrs_Names-certNames")

    certOldNames := []string{"localKeyId"}
    assertEqual(certnames, certOldNames, "P12_Attrs_Names-certNames-Equal")
}
