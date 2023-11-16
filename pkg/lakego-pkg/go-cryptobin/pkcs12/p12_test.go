package pkcs12

import (
    "testing"
    "crypto/rsa"
    "crypto/sha1"
    "crypto/rand"
    "crypto/x509"
    "encoding/hex"
    "encoding/pem"

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

    // 旧版本解析
    privateKey2, certificate2, caCerts2, err = DecodeChain(pfxData, password)
    assertError(err, "DecodeChain-pfxData")

    assertEqual(privateKey2, privateKey, "P12_EncodeChain-privateKey2")
    assertEqual(certificate2, certificates[0], "P12_EncodeChain-certificate2")
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

    secretKey2, attrs := pp12.GetSecretKey()
    assertNotEmpty(secretKey2, "P12_EncodeSecret-secretKey2")
    assertNotEmpty(attrs, "P12_EncodeSecret-secretKey2-attrs")
    assertEqual(secretKey2, secretKey, "P12_EncodeSecret-secretKey2")

    oldpass2 := sha1.Sum(secretKey)
    newpass2 := attrs.ToArray()

    assertEqual(newpass2["localKeyId"], hex.EncodeToString(oldpass2[:]), "secretKey")

    // 旧版本
    secretKeys, err := DecodeSecret(pfxData, password)
    assertError(err, "P12_EncodeSecret")

    if len(secretKeys) != 1 {
        t.Error("P12_EncodeSecret Error")
    }

    oldpass := sha1.Sum(secretKey)
    newpass := secretKeys[0].Attributes()

    assertEqual(newpass["localKeyId"], hex.EncodeToString(oldpass[:]), "secretKey")

    assertEqual(secretKeys[0].Key(), secretKey, "P12_EncodeSecret")

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

    // 旧版本
    certs, err := DecodeTrustStore(pfxData, password)
    assertError(err, "P12_DecodeTrustStore-pfxData")

    assertEqual(certs, certificates, "P12_DecodeTrustStore-certs")
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

    // 旧版本
    certificate2, err := DecodeTrustStoreEntries(pfxData, password)
    assertError(err, "P12_EncodeTrustStoreEntries-pfxData2")

    attrs := certificate2[0].Attributes()

    assertEqual(certificate2[0].Cert(), certificates[0], "P12_EncodeTrustStoreEntries-certificate2")

    assertEqual(attrs["friendlyName"], "FriendlyName-Test", "P12_EncodeTrustStoreEntries-friendlyName")
    assertEqual(attrs["javaTrustStore"], "2.5.29.37.0", "P12_EncodeTrustStoreEntries-friendlyName")
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
