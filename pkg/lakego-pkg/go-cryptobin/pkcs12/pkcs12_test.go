package pkcs12

import (
    "testing"
    "crypto/rsa"
    "crypto/tls"
    "crypto/sha1"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"
    "encoding/hex"
    "encoding/base64"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
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

func Test_EncodeSecret(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    secretKey := []byte("test-password")
    password := "passpass word"

    pfxData, err := EncodeSecret(rand.Reader, secretKey, password, DefaultOpts)
    assertError(err, "EncodeSecret")

    secretKeys, err := DecodeSecret(pfxData, password)
    assertError(err, "DecodeSecret")

    if len(secretKeys) != 1 {
        t.Error("DecodeSecret Error")
    }

    oldpass := sha1.Sum(secretKey)
    newpass := secretKeys[0].Attributes()

    assertEqual(newpass["localKeyId"], hex.EncodeToString(oldpass[:]), "secretKey")

    assertEqual(secretKeys[0].Key(), secretKey, "EncodeSecret")
}

func Test_EncodeSecret_Passwordless(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    secretKey := []byte("test-password")
    password := ""

    pfxData, err := EncodeSecret(rand.Reader, secretKey, password, PasswordlessOpts)
    assertError(err, "EncodeSecret-Passwordless")

    secretKeys, err := DecodeSecret(pfxData, password)
    assertError(err, "DecodeSecret-Passwordless")

    if len(secretKeys) != 1 {
        t.Error("DecodeSecret Error")
    }

    oldpass := sha1.Sum(secretKey)
    newpass := secretKeys[0].Attributes()

    assertEqual(newpass["localKeyId"], hex.EncodeToString(oldpass[:]), "secretKey")

    assertEqual(secretKeys[0].Key(), secretKey, "EncodeSecret-Passwordless")
}

var caCert = `
-----BEGIN CERTIFICATE-----
MIIDbTCCAlWgAwIBAgIQAJHs2CT5Pzi/46ZOhdGusTANBgkqhkiG9w0BAQsFADAV
MRMwEQYDVQQDDApnaXRodWIuY29tMB4XDTIyMDkwOTAyNDkyMloXDTMyMDkwNjAy
NDkyMlowFTETMBEGA1UEAwwKZ2l0aHViLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAKsLdJmjBih0/+lhbT5RlqpDef0/gO+LeQVpE6LDLw45uYPx
vknOFbHWrRuuu//jroWcOYNsrLX/ci57vyFH6mM06/MxrUu6tFSXxbYl48quipcb
KgFoEuNLwn1fuc1lMNq2t94cC3tHgfWDjNHB4FA7zHYYWfX5t4pPktKaPP8Uo726
ntC4VX+RoMbX6diul5fO8F7tXwtpOaaTmzti2XLBUbWHQGpudfjE6losyrsWZ7SS
w8FuKYcjoXiI1IOhq+9sAqmuGPJwJWFV/qEDzVonDCriTdE3u4JR1BmcHgguBnDp
Xf1/01wOVRce6ljtrrtey4qxieqGKu6cu9WEhm8CAwEAAaOBuDCBtTAVBgNVHREE
DjAMggpnaXRodWIuY29tMB0GA1UdDgQWBBSVT+T++EKY2x6eM2EVG8GuMTL5OjAO
BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zA7BgNVHSUENDAyBggrBgEF
BQcDAgYIKwYBBQUHAwEGCCsGAQUFBwMDBggrBgEFBQcDBAYIKwYBBQUHAwgwHwYD
VR0jBBgwFoAUlU/k/vhCmNsenjNhFRvBrjEy+TowDQYJKoZIhvcNAQELBQADggEB
AHEaGp+1WlgVWZh+Khn0cnqzmWhixLUlpaOzHIjfob3+DfdVVuShbwhIOk7+rtv8
nLGZAFKvC9zcR4JT1GEARSu5UJCwbIanaTAxXSZvpfQnuSpvf2sazumdX1BoOdOP
a8pQ/QWkgdNXO19Co/XKYaHlZsFSAt2UNTy1WEANxcw/JLdKKENmFvhO9r6dWp/8
a1eWkjUETqAnYHnCvOl7Y3cqb6bKpRF89g923VPjr/kzLHcHzIpKVxpDQz3sLKN4
abSw3VJ3HP+iQ27b65yP+E7pr1PE8hEDhApFliWvKLW7uGx9v7M7ukuSt37acKy1
M/XkkXfOEjWtKqd5FepSAIU=
-----END CERTIFICATE-----
`
var certificate = `
-----BEGIN CERTIFICATE-----
MIIDTDCCAjSgAwIBAgIQAKUxXiUjuCQwQhAxfRz2UzANBgkqhkiG9w0BAQsFADAV
MRMwEQYDVQQDDApnaXRodWIuY29tMB4XDTIyMDkwOTAyNTY0OFoXDTMyMDkwNzAy
NTY0OFowFTETMBEGA1UEAwwKZ2l0aHViLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAIM0DBC9QSpFvIzY2muwz2Oms+2EAAj3nyLxvZ1vDGcA3NXy
Zoc6sKt4n9x2wH4m1UlHPpm8jmlgixVx1aLO6n1RapFFuq8T72rJQnx05+Wfo9lh
pE65o+zGibt4Hgw6WcChfaSpyL/C490ih6pbGQVvvV0IkalRzm1AzTbXriSxkiv/
MovHvdkmN8DsgFnowK2MRBAZPqT8p31ch+CyehRKuQvyGhQoyKXyI5YnLJP6lYh9
zcHr4VfVByIho23FuNW8xmvJ+foL90wXu17E3CWquO4IahJq4zuwsVSI3s5v9g8Z
PXD9/F0mEtifEo4nztDwdFHWbFkQmy7ieKwsRu0CAwEAAaOBlzCBlDAVBgNVHREE
DjAMggpnaXRodWIuY29tMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFK6IfWox0KiL
HjqgTBHo9YscTCnHMA4GA1UdDwEB/wQEAwIEsDAdBgNVHSUEFjAUBggrBgEFBQcD
AgYIKwYBBQUHAwEwHwYDVR0jBBgwFoAUlU/k/vhCmNsenjNhFRvBrjEy+TowDQYJ
KoZIhvcNAQELBQADggEBAElshxG3pzbDtwNJXt2F+RBpVlBN5tQtFyhR4ws/ORRO
mISfu+FRBo5lQCsJHZh4eP3q6ssgGyasRVIyv9yshG/MTcbjZnuivZw2t0F/EkTz
KHcj/PwprC5Qcs6Hq71344LsW/GdXnqA4KpzJhyc3BGUZS676AVCskXYfGml8dN9
YvX7ntOZVGzfv+gK7G/EBM7YCmGZFpxNi6OFMOzNljdJIJmxON+9+QBvfCD4nN7K
dGW3DQGZNm7K60G2Z5FTL/7x7EQ4ZFX6Ls3XVoJ3qqXh7aHybCQtkAvAMUemug7L
yi/7J8xpalLI6rWhqBtxXFFL7l363cilCRx7vxSd578=
-----END CERTIFICATE-----
`
var privateKey = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCrC3SZowYodP/p
YW0+UZaqQ3n9P4Dvi3kFaROiwy8OObmD8b5JzhWx1q0brrv/466FnDmDbKy1/3Iu
e78hR+pjNOvzMa1LurRUl8W2JePKroqXGyoBaBLjS8J9X7nNZTDatrfeHAt7R4H1
g4zRweBQO8x2GFn1+beKT5LSmjz/FKO9up7QuFV/kaDG1+nYrpeXzvBe7V8LaTmm
k5s7YtlywVG1h0BqbnX4xOpaLMq7Fme0ksPBbimHI6F4iNSDoavvbAKprhjycCVh
Vf6hA81aJwwq4k3RN7uCUdQZnB4ILgZw6V39f9NcDlUXHupY7a67XsuKsYnqhiru
nLvVhIZvAgMBAAECggEAS6eD+eaxNRjXDqewtbVJwmKZJQo/IfUbYOjCriXN/OlM
ZI97HtMAJopxRALMFdljmqZoi/h4BgIIQ4YpmnNgOWQxjv5ki8/3rkj5QuFMeZwt
Ibv6nuelHxMl4eWC3dYJv1u9RQk7jNoqoej/UtIBwQtKGtwXgmRjKdKbevqMyzfh
AR3q12HxyznliXYjlTcrHki+x9MFQuc1wbu+8c9YeTr69SpGkgAlGZhDsuvEZ6fO
5vd4nhAAOcHvHJbO2DC1LwkR2Qv6JJlJbw4XO7FJUwgB0P1+J1bAdudaJtfqz4RX
NXkxWHWmCEg4+aoeI52/46sLw2MmfGv1Mt0zzRP2lQKBgQDcJWg61dD3IbUg+LN3
WGNmIyhGBx9vZI4dQE567YIPvvTPKBOFosNLUUAOY04SiUSaZtAxHsLVRCyfKU3b
1kSAd7BWKgy2//WNsLBH8gJ1gQYnfxKzVWGmazS3WNsXp4f4UVQRc9PYWAvVabkk
WCG+5EWkDWFEU2OJK8cyRVxkGwKBgQDG5tsOhT2YxqYGXtR3Im50OK7DYj/TNN+w
SBs7n6ZZGxdb2QHKEI1dO+siDHMmd+4aBif/BdcgOql2MwGE9H71tpn/D+2WRuT1
Ick8P0HNp/hT3OE+LfP6d3hiX53tdvo9CZFBe+P1WLWbHzPVao7WOtu1381RD8yR
ovMCu1TEPQKBgHp2kLHSCcnARYtO7j7gu4Kw4hF6muETlf7tq/q0LtrlhjfK+nkn
nu5CB5k5Ys/q7m/Z68y3aPjMUOpFRtuZKUgxzLVR9PrEDmxAsv+CwB1vpeXIybVb
NNQn5Q5tbouNFZVsYJDI1zsNV5/jjSuLn1IamCb3jnk8zi0bXlc3wHqrAoGBAJg0
uvb+oSdTBGOll8Le91U6twnPGnZeZLq6QxS6VAql/5cKliLxzavGGWYBzvBmIC+L
/HlcF8aS/XD1ETmT+7++D1Qu9SnlcHnhc+QFqC5fVlmekkMJ2UUWvWnSL8EzJcUl
mCFbVBNA4iAlnX24QDvR6KXh8HUSuQHNh1bU0cYlAoGAMcHuW3f/Tm3IXCG9Ssmp
ZmZrnVaXRRjGWpEVAq6SOuDxfSWoM1VdBHZJYiaC3vzStc8dFdzi8MHPlSpGEbiN
s7GpWms8Umk85u0QRJ48S1MRPQ0VMXWKjzYRyjBtmUXaRRKVhm5RhLJ+1O1AzcVV
i3iRrMnLQscEpZzE4P+guWM=
-----END PRIVATE KEY-----
`

var testOpt = Opts{
    KeyCipher: GetPbes1CipherFromName("SHA1AndRC2_40"),
    CertCipher: CipherSHA1AndRC2_40,
    MacKDFOpts: MacOpts{
        SaltSize: 8,
        IterationCount: 1,
        HMACHash: SHA1,
    },
}

func Test_Encode(t *testing.T) {
    test_Encode(t, testOpt, "password-testkjjj", "testOpt")
    test_Encode(t, LegacyRC2Opts, "password-testkjjj", "LegacyRC2Opts")
    test_Encode(t, LegacyDESOpts, "password-testkjjj", "LegacyDESOpts")
    test_Encode(t, Modern2023Opts, "passwordpasswordpasswordpassword", "Modern2023Opts")
}

func test_Encode(t *testing.T, opts Opts, password string, name string) {
    t.Run(name, func(t *testing.T) {
        assertEqual := cryptobin_test.AssertEqualT(t)
        assertError := cryptobin_test.AssertErrorT(t)
        assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

        certificates, err := x509.ParseCertificates(decodePEM(certificate))
        assertError(err, "Encode-certificates")

        parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
        assertError(err, "Encode-privateKey")

        privateKey, ok := parsedKey.(*rsa.PrivateKey)
        if !ok {
            t.Error("Encode rsa Error")
        }

        pfxData, err := Encode(rand.Reader, privateKey, certificates[0], password, opts)
        assertError(err, "Encode-pfxData")

        assertNotEmpty(pfxData, "Encode-pfxData")

        // t.Error(string(encodePEM(pfxData, "Data")))

        privateKey2, certificate2, err := Decode(pfxData, password)
        assertError(err, "Decode-pfxData")

        assertEqual(privateKey2, privateKey, "Decode-privateKey2")
        assertEqual(certificate2, certificates[0], "Decode-certificate2")
    })
}

func Test_Encode_Passwordless(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "Encode-certificates")

    parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
    assertError(err, "Encode-privateKey")

    privateKey, ok := parsedKey.(*rsa.PrivateKey)
    if !ok {
        t.Error("Encode rsa Error")
    }

    password := ""

    pfxData, err := Encode(rand.Reader, privateKey, certificates[0], password, PasswordlessOpts)
    assertError(err, "Encode-pfxData")

    assertNotEmpty(pfxData, "Encode-pfxData")

    privateKey2, certificate2, err := Decode(pfxData, password)
    assertError(err, "Decode-pfxData")

    assertEqual(privateKey2, privateKey, "Decode-privateKey2")
    assertEqual(certificate2, certificates[0], "Decode-certificate2")
}

func Test_EncodeChain(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    caCerts, err := x509.ParseCertificates(decodePEM(caCert))
    assertError(err, "EncodeChain-caCerts")

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "EncodeChain-certificates")

    parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
    assertError(err, "EncodeChain-privateKey")

    privateKey, ok := parsedKey.(*rsa.PrivateKey)
    if !ok {
        t.Error("EncodeChain rsa Error")
    }

    password := "password-testkjjj"

    pfxData, err := EncodeChain(rand.Reader, privateKey, certificates[0], caCerts, password, Opts{
        KeyCipher: GetPbes1CipherFromName("SHA1AndRC2_40"),
        CertCipher: CipherSHA1AndRC2_40,
        MacKDFOpts: MacOpts{
            SaltSize: 8,
            IterationCount: 1,
            HMACHash: SHA1,
        },
    })
    assertError(err, "EncodeChain-pfxData")

    assertNotEmpty(pfxData, "EncodeChain-pfxData")

    privateKey2, certificate2, caCerts2, err := DecodeChain(pfxData, password)
    assertError(err, "DecodeChain-pfxData")

    assertEqual(privateKey2, privateKey, "EncodeChain-privateKey2")
    assertEqual(certificate2, certificates[0], "EncodeChain-certificate2")
    assertEqual(caCerts2, caCerts, "EncodeChain-caCerts2")
}

func Test_EncodeChain_Passwordless(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    caCerts, err := x509.ParseCertificates(decodePEM(caCert))
    assertError(err, "EncodeChain-caCerts")

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "EncodeChain-certificates")

    parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
    assertError(err, "EncodeChain-privateKey")

    privateKey, ok := parsedKey.(*rsa.PrivateKey)
    if !ok {
        t.Error("EncodeChain rsa Error")
    }

    password := ""

    pfxData, err := EncodeChain(rand.Reader, privateKey, certificates[0], caCerts, password, PasswordlessOpts)
    assertError(err, "EncodeChain-pfxData")

    assertNotEmpty(pfxData, "EncodeChain-pfxData")

    privateKey2, certificate2, caCerts2, err := DecodeChain(pfxData, password)
    assertError(err, "DecodeChain-pfxData")

    assertEqual(privateKey2, privateKey, "EncodeChain-privateKey2")
    assertEqual(certificate2, certificates[0], "EncodeChain-certificate2")
    assertEqual(caCerts2, caCerts, "EncodeChain-caCerts2")
}

func Test_EncodeTrustStore(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "EncodeTrustStore-certificates")

    password := "password-testkjjj"

    pfxData, err := EncodeTrustStore(rand.Reader, certificates, password, Opts{
        KeyCipher: GetPbes1CipherFromName("SHA1AndRC2_40"),
        CertCipher: CipherSHA1AndRC2_40,
        MacKDFOpts: MacOpts{
            SaltSize: 8,
            IterationCount: 1,
            HMACHash: SHA1,
        },
    })
    assertError(err, "EncodeTrustStore-pfxData")

    assertNotEmpty(pfxData, "EncodeTrustStore-pfxData")

    certs, err := DecodeTrustStore(pfxData, password)
    assertError(err, "DecodeTrustStore-pfxData")

    assertEqual(certs, certificates, "DecodeTrustStore-privateKey2")
}

func Test_EncodeTrustStore_Passwordless(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "EncodeTrustStore-certificates")

    password := ""

    pfxData, err := EncodeTrustStore(rand.Reader, certificates, password, PasswordlessOpts)
    assertError(err, "EncodeTrustStore-pfxData")

    assertNotEmpty(pfxData, "EncodeTrustStore-pfxData")

    certs, err := DecodeTrustStore(pfxData, password)
    assertError(err, "DecodeTrustStore-pfxData")

    assertEqual(certs, certificates, "DecodeTrustStore-privateKey2")
}

func Test_EncodeTrustStoreEntries(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "EncodeTrustStoreEntries-certificates")

    password := "password-testkjjj"

    entries := make([]TrustStoreEntry, 0)
    entries = append(entries, TrustStoreEntry{
        certificates[0],
        "FriendlyName-Test",
    })

    pfxData, err := EncodeTrustStoreEntries(rand.Reader, entries, password, Opts{
        KeyCipher: GetPbes1CipherFromName("SHA1AndRC2_40"),
        CertCipher: CipherSHA1AndRC2_40,
        MacKDFOpts: MacOpts{
            SaltSize: 8,
            IterationCount: 1,
            HMACHash: SHA1,
        },
    })
    assertError(err, "EncodeTrustStoreEntries-pfxData")

    assertNotEmpty(pfxData, "EncodeTrustStoreEntries-pfxData")

    certificate2, err := DecodeTrustStoreEntries(pfxData, password)
    assertError(err, "EncodeTrustStoreEntries-pfxData2")

    attrs := certificate2[0].Attributes()

    assertEqual(certificate2[0].Cert(), certificates[0], "EncodeTrustStoreEntries-certificate2")

    assertEqual(attrs["friendlyName"], "FriendlyName-Test", "EncodeTrustStoreEntries-friendlyName")
    assertEqual(attrs["javaTrustStore"], "2.5.29.37.0", "EncodeTrustStoreEntries-friendlyName")
}

func Test_EncodeTrustStoreEntries_Passwordless(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "EncodeTrustStoreEntries-certificates")

    password := ""

    entries := make([]TrustStoreEntry, 0)
    entries = append(entries, TrustStoreEntry{
        certificates[0],
        "FriendlyName-Test",
    })

    pfxData, err := EncodeTrustStoreEntries(rand.Reader, entries, password, PasswordlessOpts)
    assertError(err, "EncodeTrustStoreEntries-pfxData")

    assertNotEmpty(pfxData, "EncodeTrustStoreEntries-pfxData")

    certificate2, err := DecodeTrustStoreEntries(pfxData, password)
    assertError(err, "EncodeTrustStoreEntries-pfxData2")

    attrs := certificate2[0].Attributes()

    assertEqual(certificate2[0].Cert(), certificates[0], "EncodeTrustStoreEntries-certificate2")

    assertEqual(attrs["friendlyName"], "FriendlyName-Test", "EncodeTrustStoreEntries-friendlyName")
    assertEqual(attrs["javaTrustStore"], "2.5.29.37.0", "EncodeTrustStoreEntries-friendlyName")
}

// ======================

func TestPfx(t *testing.T) {
    for commonName, base64P12 := range testdata {
        p12, _ := base64.StdEncoding.DecodeString(base64P12)

        priv, cert, err := Decode(p12, "")
        if err != nil {
            t.Fatal(err)
        }

        if err := priv.(*rsa.PrivateKey).Validate(); err != nil {
            t.Errorf("error while validating private key: %v", err)
        }

        if cert.Subject.CommonName != commonName {
            t.Errorf("expected common name to be %q, but found %q", commonName, cert.Subject.CommonName)
        }
    }
}

func TestPEM(t *testing.T) {
    for commonName, base64P12 := range testdata {
        p12, _ := base64.StdEncoding.DecodeString(base64P12)

        blocks, err := ToPEM(p12, "")
        if err != nil {
            t.Fatalf("error while converting to PEM: %s", err)
        }

        var pemData []byte
        for _, b := range blocks {
            pemData = append(pemData, pem.EncodeToMemory(b)...)
        }

        cert, err := tls.X509KeyPair(pemData, pemData)
        if err != nil {
            t.Errorf("err while converting to key pair: %v", err)
        }
        config := tls.Config{
            Certificates: []tls.Certificate{cert},
        }
        config.BuildNameToCertificate()

        if _, exists := config.NameToCertificate[commonName]; !exists {
            t.Errorf("did not find our cert in PEM?: %v", config.NameToCertificate)
        }
    }
}

func ExampleToPEM() {
    p12, _ := base64.StdEncoding.DecodeString(`MIIJzgIBAzCCCZQGCS ... CA+gwggPk==`)

    blocks, err := ToPEM(p12, "password")
    if err != nil {
        panic(err)
    }

    var pemData []byte
    for _, b := range blocks {
        pemData = append(pemData, pem.EncodeToMemory(b)...)
    }

    // then use PEM data for tls to construct tls certificate:
    cert, err := tls.X509KeyPair(pemData, pemData)
    if err != nil {
        panic(err)
    }

    config := &tls.Config{
        Certificates: []tls.Certificate{cert},
    }

    _ = config
}

var testdata = map[string]string{
    // 'null' password test case
    "Windows Azure Tools": `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`,
    // Windows IAS PEAP & LDAPS certificates test case
    // Unknown OID 1.3.6.1.4.1.311.17.2 should be dropped
    "Windows IAS PEAP & LDAPS certificates": `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`,
    // empty string password test case
    "testing@example.com": `MIIJzgIBAzCCCZQGCSqGSIb3DQEHAaCCCYUEggmBMIIJfTCCA/cGCSqGSIb3DQEHBqCCA+gwggPk
AgEAMIID3QYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIIszfRGqcmPcCAggAgIIDsOZ9Eg1L
s5Wx8JhYoV3HAL4aRnkAWvTYB5NISZOgSgIQTssmt/3A7134dibTmaT/93LikkL3cTKLnQzJ4wDf
YZ1bprpVJvUqz+HFT79m27bP9zYXFrvxWBJbxjYKTSjQMgz+h8LAEpXXGajCmxMJ1oCOtdXkhhzc
LdZN6SAYgtmtyFnCdMEDskSggGuLb3fw84QEJ/Sj6FAULXunW/CPaS7Ce0TMsKmNU/jfFWj3yXXw
ro0kwjKiVLpVFlnBlHo2OoVU7hmkm59YpGhLgS7nxLD3n7nBroQ0ID1+8R01NnV9XLGoGzxMm1te
6UyTCkr5mj+kEQ8EP1Ys7g/TC411uhVWySMt/rcpkx7Vz1r9kYEAzJpONAfr6cuEVkPKrxpq4Fh0
2fzlKBky0i/hrfIEUmngh+ERHUb/Mtv/fkv1j5w9suESbhsMLLiCXAlsP1UWMX+3bNizi3WVMEts
FM2k9byn+p8IUD/A8ULlE4kEaWeoc+2idkCNQkLGuIdGUXUFVm58se0auUkVRoRJx8x4CkMesT8j
b1H831W66YRWoEwwDQp2kK1lA2vQXxdVHWlFevMNxJeromLzj3ayiaFrfByeUXhR2S+Hpm+c0yNR
4UVU9WED2kacsZcpRm9nlEa5sr28mri5JdBrNa/K02OOhvKCxr5ZGmbOVzUQKla2z4w+Ku9k8POm
dfDNU/fGx1b5hcFWtghXe3msWVsSJrQihnN6q1ughzNiYZlJUGcHdZDRtiWwCFI0bR8h/Dmg9uO9
4rawQQrjIRT7B8yF3UbkZyAqs8Ppb1TsMeNPHh1rxEfGVQknh/48ouJYsmtbnzugTUt3mJCXXiL+
XcPMV6bBVAUu4aaVKSmg9+yJtY4/VKv10iw88ktv29fViIdBe3t6l/oPuvQgbQ8dqf4T8w0l/uKZ
9lS1Na9jfT1vCoS7F5TRi+tmyj1vL5kr/amEIW6xKEP6oeAMvCMtbPAzVEj38zdJ1R22FfuIBxkh
f0Zl7pdVbmzRxl/SBx9iIBJSqAvcXItiT0FIj8HxQ+0iZKqMQMiBuNWJf5pYOLWGrIyntCWwHuaQ
wrx0sTGuEL9YXLEAsBDrsvzLkx/56E4INGZFrH8G7HBdW6iGqb22IMI4GHltYSyBRKbB0gadYTyv
abPEoqww8o7/85aPSzOTJ/53ozD438Q+d0u9SyDuOb60SzCD/zPuCEd78YgtXJwBYTuUNRT27FaM
3LGMX8Hz+6yPNRnmnA2XKPn7dx/IlaqAjIs8MIIFfgYJKoZIhvcNAQcBoIIFbwSCBWswggVnMIIF
YwYLKoZIhvcNAQwKAQKgggTuMIIE6jAcBgoqhkiG9w0BDAEDMA4ECJr0cClYqOlcAgIIAASCBMhe
OQSiP2s0/46ONXcNeVAkz2ksW3u/+qorhSiskGZ0b3dFa1hhgBU2Q7JVIkc4Hf7OXaT1eVQ8oqND
uhqsNz83/kqYo70+LS8Hocj49jFgWAKrf/yQkdyP1daHa2yzlEw4mkpqOfnIORQHvYCa8nEApspZ
wVu8y6WVuLHKU67mel7db2xwstQp7PRuSAYqGjTfAylElog8ASdaqqYbYIrCXucF8iF9oVgmb/Qo
xrXshJ9aSLO4MuXlTPELmWgj07AXKSb90FKNihE+y0bWb9LPVFY1Sly3AX9PfrtkSXIZwqW3phpv
MxGxQl/R6mr1z+hlTfY9Wdpb5vlKXPKA0L0Rt8d2pOesylFi6esJoS01QgP1kJILjbrV731kvDc0
Jsd+Oxv4BMwA7ClG8w1EAOInc/GrV1MWFGw/HeEqj3CZ/l/0jv9bwkbVeVCiIhoL6P6lVx9pXq4t
KZ0uKg/tk5TVJmG2vLcMLvezD0Yk3G2ZOMrywtmskrwoF7oAUpO9e87szoH6fEvUZlkDkPVW1NV4
cZk3DBSQiuA3VOOg8qbo/tx/EE3H59P0axZWno2GSB0wFPWd1aj+b//tJEJHaaNR6qPRj4IWj9ru
Qbc8eRAcVWleHg8uAehSvUXlFpyMQREyrnpvMGddpiTC8N4UMrrBRhV7+UbCOWhxPCbItnInBqgl
1JpSZIP7iUtsIMdu3fEC2cdbXMTRul+4rdzUR7F9OaezV3jjvcAbDvgbK1CpyC+MJ1Mxm/iTgk9V
iUArydhlR8OniN84GyGYoYCW9O/KUwb6ASmeFOu/msx8x6kAsSQHIkKqMKv0TUR3kZnkxUvdpBGP
KTl4YCTvNGX4dYALBqrAETRDhua2KVBD/kEttDHwBNVbN2xi81+Mc7ml461aADfk0c66R/m2sjHB
2tN9+wG12OIWFQjL6wF/UfJMYamxx2zOOExiId29Opt57uYiNVLOO4ourPewHPeH0u8Gz35aero7
lkt7cZAe1Q0038JUuE/QGlnK4lESK9UkSIQAjSaAlTsrcfwtQxB2EjoOoLhwH5mvxUEmcNGNnXUc
9xj3M5BD3zBz3Ft7G3YMMDwB1+zC2l+0UG0MGVjMVaeoy32VVNvxgX7jk22OXG1iaOB+PY9kdk+O
X+52BGSf/rD6X0EnqY7XuRPkMGgjtpZeAYxRQnFtCZgDY4wYheuxqSSpdF49yNczSPLkgB3CeCfS
+9NTKN7aC6hBbmW/8yYh6OvSiCEwY0lFS/T+7iaVxr1loE4zI1y/FFp4Pe1qfLlLttVlkygga2UU
SCunTQ8UB/M5IXWKkhMOO11dP4niWwb39Y7pCWpau7mwbXOKfRPX96cgHnQJK5uG+BesDD1oYnX0
6frN7FOnTSHKruRIwuI8KnOQ/I+owmyz71wiv5LMQt+yM47UrEjB/EZa5X8dpEwOZvkdqL7utcyo
l0XH5kWMXdW856LL/FYftAqJIDAmtX1TXF/rbP6mPyN/IlDC0gjP84Uzd/a2UyTIWr+wk49Ek3vQ
/uDamq6QrwAxVmNh5Tset5Vhpc1e1kb7mRMZIzxSP8JcTuYd45oFKi98I8YjvueHVZce1g7OudQP
SbFQoJvdT46iBg1TTatlltpOiH2mFaxWVS0xYjAjBgkqhkiG9w0BCRUxFgQUdA9eVqvETX4an/c8
p8SsTugkit8wOwYJKoZIhvcNAQkUMS4eLABGAHIAaQBlAG4AZABsAHkAIABuAGEAbQBlACAAZgBv
AHIAIABjAGUAcgB0MDEwITAJBgUrDgMCGgUABBRFsNz3Zd1O1GI8GTuFwCWuDOjEEwQIuBEfIcAy
HQ8CAggA`,
}

// ======================

var testNewPfx_Encode = `
-----BEGIN Data-----
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
-----END Data-----
`
var testNewPfx_EncodeTrustStore = `
-----BEGIN Data-----
MIIEXgIBAzCCBCoGCSqGSIb3DQEHAaCCBBsEggQXMIIEEzCCBA8GCSqGSIb3DQEH
BqCCBAAwggP8AgEAMIID9QYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQI0sXG
GhN6z4MCAggAgIIDyOUYg7pbF+PQw2ZtYaPOJQ+8WvEORmejBGB7yCsdmhQkvrWd
TfMCqsIc39ZMfWsUyV9aayVafp7qVag2/S/3ADw6arxmeLeXHsDtjI0CgriLYDQt
8ivjNM85vvkdU4x4EkTI6sWR2G7qlS1F1ued8CQbyCSPCnSjLNme7Qbxh7MGUgX8
B/25TOOfcGAvFmlOurqUzF5kSL53tg5T+TvbmtyMYSkuv1yIcZJYboTgckRKjjDo
mUn3SMuVkXKWCMPfRcuCOVernI01T56Q+7lU5zn9jvpZ2qg0H5UVY5TSd+fIuYiX
VYwxxISYyobDW833dNlds6pvhnDRZlxvVo2q50bXrQ0CtTtDrsRIgNNNdqnXi5SJ
WWnSiwZogFeXGnDtCuOy+Fkg4M+/Ey2pBEVaWbCBogtl9czIisQc1bD63gTtepoy
ZPpFw0uJxQMzkefTvcf5ZL+O0PTc0wP1KLAD18+uu32+KxYmdHz4iFVa2N7+mD/t
NDRqDKCAnegsjoo9SNhUuNFSTYX1Eei+fiHuOyJF6MApjurQ4m5h/rTQi480q98a
caGax7THyjX4rP1V+w4TuyLj4gjZ1RNFGyEjZxz6zJdIQ7QQvYPFBrB9HvyruBY9
w6eJd1zp/kZm32AjaUApB222sQw+TDYPRor6SaT3wsCupUixQmJtE3BGJsDNCU4Y
EMVKp2/22wHLgSXcguj7X3kf6udVRiYUuR8qCsHF+gnYr2BkY91Jly0TQhMHjjxP
Wc4/0v6ShAWy3Qr65iNPxOWw3W6OlLJjt1cFbQfwfRnfSW1cp1mxO3YFNwJ7ee/G
jxmTKnUj5GwQfPJWtybEWoZxPJG8HcKejdiVH7o8+ITnFPaQPlqpOf8tbryrNDMi
l77ygVG8b3hyHAm7m6rfV5+TnnAkACbQVXJc8dhsDyRAGdu8e75x+twKI/QW7y52
JSREQLZ2lzwzkrWySfTxv8BM86M5pXcNqR4c+LRy3aZBjrUzBH0J74SP26sVjWrP
I6i8z53eG5TmihBAPzF8+6l6XUMp9cdjex0Af3gRCpLKRPAxm5gGC9XlMnBSfpn1
g6P3gmsJeHfa8XVXUju+H7m7wz4m1sU0dfjKMvVXNN/uGtlOq6Vt7qisE0X0Yn6G
Qq95gf2o5dMSE1z2LgebIJkSew54IF8tBWC7nclGGHBqtfnSTtetlRX5myvc4saB
cXsRkeDiujMvA7kz6Vrxs9RNs2crDTdxG2trmM9bNJ5fcIJmiLzGWdzm76Mb+oBP
hpBvQTrd3nk4MQ0gW6+TEH41WmS9MCswHzAHBgUrDgMCGgQUhCEuVk8TABfWMBcA
BQamSGGwvAcECJQ5KEpsGh9o
-----END Data-----
`
var testNewPfxPbes2_Encode = `
-----BEGIN Data-----
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
EL4Z9a1+ztrTRegpcicaNNUCAggA
-----END Data-----
`
var testNewPfxDes_Encode = `
-----BEGIN Data-----
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
-----END Data-----
`
var testNewPfxCa_Encode = `
-----BEGIN Data-----
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
5uI3VXMECMWUavV4eajI
-----END Data-----
`

func Test_Encode_Check(t *testing.T) {
    t.Run("Encode_Check", func(t *testing.T) {
        assertEqual := cryptobin_test.AssertEqualT(t)
        assertError := cryptobin_test.AssertErrorT(t)

        certificates, err := x509.ParseCertificates(decodePEM(certificate))
        assertError(err, "Encode_Check-certificates")

        parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
        assertError(err, "Encode_Check-privateKey")

        privateKey, ok := parsedKey.(*rsa.PrivateKey)
        if !ok {
            t.Error("Encode_Check rsa Error")
        }

        pfxData := decodePEM(testNewPfx_Encode)

        password := "pass"

        privateKey2, certificate2, err := Decode(pfxData, password)
        assertError(err, "Encode_Check-pfxData")

        assertEqual(privateKey2, privateKey, "Encode_Check-privateKey2")
        assertEqual(certificate2, certificates[0], "Encode_Check-certificate2")
    })
}

func Test_EncodeTrustStore_Check(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "EncodeTrustStore_Check-certificates")

    pfxData := decodePEM(testNewPfx_EncodeTrustStore)

    password := "pass"

    certs, err := DecodeTrustStore(pfxData, password)
    assertError(err, "EncodeTrustStore_Check-pfxData")

    assertEqual(certs, certificates, "EncodeTrustStore_Check-privateKey2")
}

func Test_EncodeDes_Check(t *testing.T) {
    t.Run("EncodeDes_Check", func(t *testing.T) {
        assertEqual := cryptobin_test.AssertEqualT(t)
        assertError := cryptobin_test.AssertErrorT(t)

        certificates, err := x509.ParseCertificates(decodePEM(certificate))
        assertError(err, "EncodeDes_Check-certificates")

        parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
        assertError(err, "EncodeDes_Check-privateKey")

        privateKey, ok := parsedKey.(*rsa.PrivateKey)
        if !ok {
            t.Error("EncodeDes_Check rsa Error")
        }

        pfxData := decodePEM(testNewPfxDes_Encode)

        password := "pass"

        privateKey2, certificate2, err := Decode(pfxData, password)
        assertError(err, "EncodeDes_Check-pfxData")

        assertEqual(privateKey2, privateKey, "EncodeDes_Check-privateKey2")
        assertEqual(certificate2, certificates[0], "EncodeDes_Check-certificate2")
    })
}

func Test_EncodePbes2_Check(t *testing.T) {
    t.Run("EncodePbes2_Check", func(t *testing.T) {
        assertEqual := cryptobin_test.AssertEqualT(t)
        assertError := cryptobin_test.AssertErrorT(t)

        certificates, err := x509.ParseCertificates(decodePEM(certificate))
        assertError(err, "EncodePbes2_Check-certificates")

        parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
        assertError(err, "EncodePbes2_Check-privateKey")

        privateKey, ok := parsedKey.(*rsa.PrivateKey)
        if !ok {
            t.Error("EncodePbes2_Check rsa Error")
        }

        pfxData := decodePEM(testNewPfxPbes2_Encode)

        password := "pass"

        privateKey2, certificate2, err := Decode(pfxData, password)
        assertError(err, "EncodePbes2_Check-pfxData")

        assertEqual(privateKey2, privateKey, "EncodePbes2_Check-privateKey2")
        assertEqual(certificate2, certificates[0], "EncodePbes2_Check-certificate2")
    })
}

func Test_EncodeChain_Check(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    caCerts, err := x509.ParseCertificates(decodePEM(caCert))
    assertError(err, "EncodeChain_Check-caCerts")

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "EncodeChain_Check-certificates")

    parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
    assertError(err, "EncodeChain_Check-privateKey")

    privateKey, ok := parsedKey.(*rsa.PrivateKey)
    if !ok {
        t.Error("EncodeChain_Check rsa Error")
    }

    pfxData := decodePEM(testNewPfxCa_Encode)

    password := "pass"

    privateKey2, certificate2, caCerts2, err := DecodeChain(pfxData, password)
    assertError(err, "EncodeChain_Check-pfxData")

    assertEqual(privateKey2, privateKey, "EncodeChain_Check-privateKey2")
    assertEqual(certificate2, certificates[0], "EncodeChain_Check-certificate2")
    assertEqual(caCerts2, caCerts, "EncodeChain_Check-caCerts2")
}
