package pkcs12

import (
    "testing"
    "crypto/rsa"
    "crypto/tls"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"
    "encoding/base64"

    "github.com/deatil/go-cryptobin/pkcs8/pbes2"
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

    secretKey2, err := DecodeSecret(pfxData, password)
    assertError(err, "DecodeSecret")

    assertEqual(secretKey2, secretKey, "EncodeSecret")
}

func Test_EncodeSecret_Passwordless(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    secretKey := []byte("test-password")
    password := ""

    pfxData, err := EncodeSecret(rand.Reader, secretKey, password, PasswordlessOpts)
    assertError(err, "EncodeSecret-Passwordless")

    secretKey2, err := DecodeSecret(pfxData, password)
    assertError(err, "DecodeSecret-Passwordless")

    assertEqual(secretKey2, secretKey, "EncodeSecret-Passwordless")
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

func newTestOpt(h Hash) Opts {
    opt := Opts{
        KeyCipher: GetPbes1CipherFromName("SHA1AndRC2_40"),
        CertCipher: CipherSHA1AndRC2_40,
        MacKDFOpts: MacOpts{
            SaltSize: 8,
            IterationCount: 1,
            HMACHash: h,
        },
    }

    return opt
}

func newTestOptWithCipher(cip1, cip2 Cipher) Opts {
    opt := Opts{
        KeyCipher: cip1,
        CertCipher: cip2,
        MacKDFOpts: MacOpts{
            SaltSize: 8,
            IterationCount: 1,
            HMACHash: MD5,
        },
    }

    return opt
}

func Test_Encode(t *testing.T) {
    test_Encode(t, testOpt, "password-testkjjj", "testOpt")

    // test use hashs
    test_Encode(t, newTestOpt(MD2), "password-testkjjj", "testOpt MD2")
    test_Encode(t, newTestOpt(MD4), "password-testkjjj", "testOpt MD4")
    test_Encode(t, newTestOpt(MD5), "password-testkjjj", "testOpt MD5")
    test_Encode(t, newTestOpt(SHA1), "password-testkjjj", "testOpt SHA1")
    test_Encode(t, newTestOpt(SHA224), "password-testkjjj", "testOpt SHA224")
    test_Encode(t, newTestOpt(SHA256), "password-testkjjj", "testOpt SHA256")
    test_Encode(t, newTestOpt(SHA384), "password-testkjjj", "testOpt SHA384")
    test_Encode(t, newTestOpt(SHA512), "password-testkjjj", "testOpt SHA512")
    test_Encode(t, newTestOpt(SHA512_224), "password-testkjjj", "testOpt SHA512_224")
    test_Encode(t, newTestOpt(SHA512_256), "password-testkjjj", "testOpt SHA512_256")
    test_Encode(t, newTestOpt(SM3), "password-testkjjj", "testOpt SM3")
    test_Encode(t, newTestOpt(GOST341194), "password-testkjjj", "testOpt GOST341194")
    test_Encode(t, newTestOpt(GOST34112012256), "password-testkjjj", "testOpt GOST34112012256")
    test_Encode(t, newTestOpt(GOST34112012512), "password-testkjjj", "testOpt GOST34112012512")

    // test use Ciphers
    test_Encode(t, newTestOptWithCipher(GetPbes1CipherFromName("SHA1And3DES"), CipherSHA1And3DES), "password-testkjjj", "testOpt CipherSHA1And3DES")
    test_Encode(t, newTestOptWithCipher(GetPbes1CipherFromName("SHA1And2DES"), CipherSHA1And2DES), "password-testkjjj", "testOpt CipherSHA1And2DES")
    test_Encode(t, newTestOptWithCipher(GetPbes1CipherFromName("SHA1AndRC2_128"), CipherSHA1AndRC2_128), "password-testkjjj", "testOpt CipherSHA1AndRC2_128")
    test_Encode(t, newTestOptWithCipher(GetPbes1CipherFromName("SHA1AndRC2_40"), CipherSHA1AndRC2_40), "password-testkjjj", "testOpt CipherSHA1AndRC2_40")
    test_Encode(t, newTestOptWithCipher(GetPbes1CipherFromName("SHA1AndRC4_128"), CipherSHA1AndRC4_128), "password-testkjjj", "testOpt CipherSHA1AndRC4_128")
    test_Encode(t, newTestOptWithCipher(GetPbes1CipherFromName("SHA1AndRC4_40"), CipherSHA1AndRC4_40), "password-testkjjj", "testOpt CipherSHA1AndRC4_40")
    test_Encode(t, newTestOptWithCipher(GetPbes1CipherFromName("MD5AndCAST5"), CipherMD5AndCAST5), "password-testkjjj", "testOpt CipherMD5AndCAST5")
    test_Encode(t, newTestOptWithCipher(GetPbes1CipherFromName("SHAAndTwofish"), CipherSHAAndTwofish), "password-testkjjj", "testOpt CipherSHAAndTwofish")

    test_Encode(t, LegacyRC2Opts, "password-testkjjj", "LegacyRC2Opts")
    test_Encode(t, LegacyDESOpts, "password-testkjjj", "LegacyDESOpts")
    test_Encode(t, PasswordlessOpts, "", "PasswordlessOpts")
    test_Encode(t, Modern2023Opts, "passwordpasswordpasswordpassword", "Modern2023Opts")
    test_Encode(t, LegacyGostOpts, "passwordpasswordpasswordpassword", "LegacyGostOpts")
    test_Encode(t, LegacyGmsmOpts, "passwordpasswordpasswordpassword", "LegacyGmsmOpts")
    test_Encode(t, Shangmi2024Opts, "passwordpasswordpasswordpassword", "Shangmi2024Opts")
    test_Encode(t, LegacyPBMAC1Opts, "1234", "LegacyPBMAC1Opts")

    var LegacyPBMAC1Opts2 = Opts{
        KeyCipher:  pbes2.AES256CBC,
        KeyKDFOpts: PBKDF2Opts{
            SaltSize:       8,
            IterationCount: 2048,
        },
        CertCipher:  pbes2.AES256CBC,
        CertKDFOpts: PBKDF2Opts{
            SaltSize:       8,
            IterationCount: 2048,
        },
        MacKDFOpts: PBMAC1Opts{
            HasKeyLength:   true,
            SaltSize:       8,
            IterationCount: 2048,
            KDFHash:        PBMAC1SHA512,
            HMACHash:       PBMAC1SHA256,
        },
    }
    test_Encode(t, LegacyPBMAC1Opts2, "1234", "LegacyPBMAC1Opts2")

    var LegacyPBMAC1Opts3 = Opts{
        KeyCipher:  pbes2.AES256CBC,
        KeyKDFOpts: PBKDF2Opts{
            SaltSize:       8,
            IterationCount: 2048,
        },
        CertCipher:  pbes2.AES256CBC,
        CertKDFOpts: PBKDF2Opts{
            SaltSize:       8,
            IterationCount: 2048,
        },
        MacKDFOpts: PBMAC1Opts{
            HasKeyLength:   true,
            SaltSize:       8,
            IterationCount: 2048,
            KDFHash:        PBMAC1SHA512,
            HMACHash:       PBMAC1SHA384,
        },
    }
    test_Encode(t, LegacyPBMAC1Opts3, "1234", "LegacyPBMAC1Opts3")

    var LegacyPBMAC1Opts5 = Opts{
        KeyCipher:  pbes2.AES256CBC,
        KeyKDFOpts: PBKDF2Opts{
            SaltSize:       8,
            IterationCount: 2048,
        },
        CertCipher:  pbes2.AES256CBC,
        CertKDFOpts: PBKDF2Opts{
            SaltSize:       8,
            IterationCount: 2048,
        },
        MacKDFOpts: PBMAC1Opts{
            HasKeyLength:   true,
            SaltSize:       8,
            IterationCount: 2048,
            KDFHash:        PBMAC1SM3,
            HMACHash:       PBMAC1SM3,
        },
    }
    test_Encode(t, LegacyPBMAC1Opts5, "1234", "LegacyPBMAC1Opts5")
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
        t.Run(commonName, func(t *testing.T) {
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
        })
    }
}

func TestPEM(t *testing.T) {
    for commonName, base64P12 := range testdata {
        t.Run(commonName, func(t *testing.T) {
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
        })
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
    "testing@example.com": `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
HQ8CAggA`,
}

// ======================

// 3des
var testNewPfx_Encode = `
-----BEGIN Data-----
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
-----END Data-----
`
// RC2_40
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
MIIJiwIBAzCCCVcGCSqGSIb3DQEHAaCCCUgEgglEMIIJQDCCA/cGCSqGSIb3DQEH
BqCCA+gwggPkAgEAMIID3QYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQICDEP
AxcTdg8CAggAgIIDsHpC3ne44IpKM0uHkAmgJlwYdHjmaMtVyGlQwsEsj2JLydIQ
TOwCVN8iUScLdzKLd9HQFl6YCDn+c721Fzq5AQW8HN4y8G3Y66I7mtPorgVGWg3m
hB68N04J7dTHO1q65iA04NsA4yK8gcHF9DvYA8Ym41ZBs5uvNqx1U1McAiil8RLk
eXnb+ueFmjFe10Kk+RIyyZiYqmNWxMMSqRl9cbbQoFYFs/p1f1q15nbpaxz8t8CB
bnefVdDJLwFVVhTw8/tU7VhqpPbkZ2BqRFdGpAv39nQ/FND2/xp+nlOgaemxgTHX
5Gfi41zGsX2yu0/T9HoN6rbK8X62gms8adPob4B/QYhLbHmrkafDWzQbW055BtLy
VbToGB7p0ELpHx57CQwjsqvsglqJZhcUELQQg9nq6HdgUJFo41WucdYu4c1ArsIs
GrqYUwix6d34MmxqDVIQPZxWHxZ7xXy39VZ/D2hx/hxj+UHUhO6SAxne7lbpNfP7
lb04zFLN2ASNMg32iG5a3iEbaYa3OnTLsGvT5DMPg0sluqJdNtnErwoGgudH38QZ
49ZFG//++paVw/cs0xn+JmqacuR3f2OZ2MFJwLzW8RUqWyfixfn7IvLiseYXAFqJ
SmzF0+qLPSAuJNr87Bue0t1nPjX2YKMJqlfQhDWu1axFfb62WO001qjAhyhYniD+
Zfv2hT66mmW7yUCs87+uoYf7Ea8uclYMbrv+eEhnMtlOvvBGDynpnRXPZWT8U42D
7+NQAWsg7D5BdUMdnoOZfQE1LdARDD8Rurh+UH23DT7lzYevAswDAEhz5OcSO6QQ
sZc1EpivJ8bvGBny0odOrMq4q2EyDtR8GRQC1TldJ0+duUS25pKBJa7wzmpNGP6K
6Ys4dBL1KGK8R6be8AbOcadYKMYitDfjgGAwWXHIFzNYrcDp3TyldqxEsk0YUxRS
OX0TfavnNkm3XPYThF+HOKuk/oNeoGspQOAHwGFEAvdgNDN6xAO8hm7PbBTnfSCC
nSLMOcl+IBWHgtZhfTsLpYYug4dplUztCWmx4KeWgbORkgq1IwdZ3IljdofPmW6z
IUIpSjAPhEeaqAOZ6aWqLdrgZaGUnH8KWQYX/jnEaMShCED1xxmSQCYygbzK/bgf
oDIMwxhmyRoNL5ANX/uhp9lKV+88rawTlOKVoUqzcgFOU9HyRojF5YUC/rQGT/RL
PmuEUgUjQY0FYE9UpTM27yX0nKvchcuM61KJZ8esc/5YkIHNkSRFFQ54li1QMIIF
QQYJKoZIhvcNAQcBoIIFMgSCBS4wggUqMIIFJgYLKoZIhvcNAQwKAQKgggTuMIIE
6jAcBgoqhkiG9w0BDAEDMA4ECK22DVn/fqy0AgIIAASCBMju5RC3M+13h1OvvDoZ
bPLmotElwoExY+zsQtabPlsG1LyyGHTi15pKZuFMSgLtzoA+8C0dRPJrPaab6sKP
Rju1TN0KwNvRRQdM7cqnP01XcysKQraNteAokGLezhSu96k7r0eeZcjkC+8qXC6O
rT1pYPaQnk6Of5SwCB9LUYKFwdxZVYL7X5lDtdw5kJqF/jnnvWexDQyCKICT40xi
wQV0gAroNHdtoqtuw5bKgnldEgn7ECrZB9vWllpcFSpcd4Xye+teGic+qoGSQoFH
l0BQBTVFTna5rt2B765kIswOyNAePx15gHxPuMD6JreFYGAaIt9x4bJbQAStbaY/
Pzmnc5v2o8wKJcECFpCM+nPqLzeHRAR6kK0vNU1uhD08304cM6xpF7RMb40IOhb0
fipPUzQNI3RdaWTIuSUiZMEnZgGSIsQlWFwZSGb19h9hGOZhRO8gwVJq7MTUtML6
AJhGFDxgMwdoUPWk0RohE2hnRbQFuJSI9ipi6KUPcJxUcksyhhN5oyyxzhonZjQX
t+QJqeNiAT0vaf85Pa+2asgcDi02Gf37uXD47Yr/ACTrzi/Tcfg7Zjp+DuzdmpM5
10WxBM78t4PBabOVY4snKiPPrdlfaIJjeaVIrdjdjKWPepIPSPeFTPaYQeWN8y3a
r2UsNG7rpyes0NROq/xnk4n50sCYCw1mHCDwYMsljqc8vwgzNuTAIlPjOTpaCZmj
nVXuEcmxqPsR5eU/B8owRuCE7Z1+EM91c68Ruog2dvpf/njcQG6iZKskFWCZZ3BN
Hsxr0jwtJ2Bl5SU8CGXaZHlqiYMzY8vmSygLY6Vwjj+7Voun6wYQtwkcXo+nt+KM
eZfDj2ClNn29pxWVhF0II869oDn1ydscvZ2Rzz/FHIvOvyQhfbbRxLHDCjD9Gssy
ENhIk04jGi+L5c0fKOkWXd3SFnA0D2RBRsoB+EuMz/rUuoYB0hb+CRa4UWtnOtCk
fgX1Zxq+JDIK7NGmUk7rP3ZFgwh3fuc6jYKXUQx5tXFOsdb/mfIWdn9S0+Bmquws
xg/nmb7ijkePwjdVoImdHJSe6v5RuyfC5llSILxtyP1VT7LKRl129tmLID3G7N92
RO9zJKAM1D/g4t42E/sS1jG88Vj9dYXVw/oi6Uqba/iMJJHgT7hyUHZnYzgYxf8f
EbmYkhFSv10ku1sUSd5wtlyHbf8D9MmPdX1YjG0/p0VeCu2k/aAscDFfvEoQd8+9
Y3co0RE2VwI4BD3ZmE6/BGuGMf21PRZP5Wf7KHVXgO3Q+sHikAkpoJAASOc7XB+P
OsIwRfceYDPd3wLUQ6RwibZ++0b3oEK28RWy+8XrYyZ6EzE6kE2LzkaVc+zTO7i3
RijF17Ekhc0x0y3LwYEUr/uPCgLo74o7l+2t+33HRwCln9NkyOH7St9ThtEFTPFr
SGVEUpT88JR9o5RAksh0cLbXHDPDK/DJbptrtVsVUdXvztOZ5ZdxuBj/tuZrq2fo
8X88ZYY+kEPrj4d1RpCkfdOYZOk1CJyB6+zVrXF8wADDpR751uYmGNLtIqv1tUKI
7Yj0PDY8GwCp/32QlZ1BLtC8WuTBHIM1u4xWOEvYkOP3EbgMznXYXviTwi6K5iEn
IuoFiKClAnJOlj4xJTAjBgkqhkiG9w0BCRUxFgQUWwfyVBIx13xC1MGTBQsYb8jc
lREwKzAfMAcGBSsOAwIaBBT7WQNcyZ2b0sfrFeejlbRqYndIuwQIxLqspQeMls4=
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

func Test_ToPem(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    pfxData := decodePEM(testNewPfx_Encode)

    password := "pass"

    blocks, err := ToPEM(pfxData, password)
    assertError(err, "Test_ToPem-ToPEM")
    assertNotEmpty(blocks, "Test_ToPem-ToPEM")

    var pemData [][]byte
    for _, b := range blocks {
        pemData = append(pemData, pem.EncodeToMemory(b))
    }

    for _, pemInfo := range pemData {
        assertNotEmpty(pemInfo, "Test_ToPem-ToPEM-Pem")
    }
}

func Test_Encode_Passwordless_ToPem(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    certificates, err := x509.ParseCertificates(decodePEM(certificate))
    assertError(err, "Test_Encode_Passwordless_ToPem-certificates")

    parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
    assertError(err, "Test_Encode_Passwordless_ToPem-privateKey")

    privateKey, ok := parsedKey.(*rsa.PrivateKey)
    if !ok {
        t.Error("Test_Encode_Passwordless_ToPem rsa Error")
    }

    password := ""

    pfxData, err := Encode(rand.Reader, privateKey, certificates[0], password, PasswordlessOpts)
    assertError(err, "Test_Encode_Passwordless_ToPem-pfxData")

    // 检测
    blocks, err := ToPEM(pfxData, password)
    assertError(err, "Test_Encode_Passwordless_ToPem-ToPEM")
    assertNotEmpty(blocks, "Test_Encode_Passwordless_ToPem-ToPEM")

    var pemData [][]byte
    for _, b := range blocks {
        pemData = append(pemData, pem.EncodeToMemory(b))
    }

    for _, pemInfo := range pemData {
        assertNotEmpty(pemInfo, "Test_Encode_Passwordless_ToPem-ToPEM-Pem")
    }
}

func TestPBES2_AES256CBC(t *testing.T) {
    // This P12 PDU is a self-signed certificate exported via Windows certmgr.
    // It is encrypted with the following options (verified via openssl): PBES2, PBKDF2, AES-256-CBC, Iteration 2000, PRF hmacWithSHA256
    commonName := "*.ad.standalone.com"
    base64P12 := `MIIK1wIBAzCCCoMGCSqGSIb3DQEHAaCCCnQEggpwMIIKbDCCBkIGCSqGSIb3DQEHAaCCBjMEggYvMIIGKzCCBicGCyqGSIb3DQEMCgECoIIFMTCCBS0wVwYJKoZIhvcNAQUNMEowKQYJKoZIhvcNAQUMMBwECKESv9Fb9n1qAgIH0DAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQVfcQGG6G712YmXBYug/7aASCBNARs5FW8sl11oZG+ynkQCQKByX0ykA8sPGqz4QJ9zZVda570ZbTP0hxvWbh7eXErZ4eT0Pg68Lcp2gKMQqGLhasCTEFBk41lpAO/Xpy1ODQ/4C6PrQIF5nPBcqz+fEJ0FxxZYpvR5biy7h8CGt6QRc44i2Iu4il2YotRcX5r4tkKSyzcTCHaMq9QjpR9NmpXtTfaz+quB0EqlTfEe9cmMU1JRUX2S5orVyDE6Y+HGfg/PuRapEk45diwhTpfh+xzL3FDFCOzu17eluVaWNE2Jxrg3QvnoOQT5vRHopzOWDacHlqE2nUXGdUmuzzx2KLtjyJ/g8ofHCzzfLd32DmfRUQAhsPLVMCygv/lQukVRRnL2WJuwpP/58I1XLcsb6J48ZNCVsx/BMLNQ8GBHOuhPmmZ/ca4qNWcKALmUhh1BOE451n5eORTbJC5PwNl0r9xBa0f26ikDtWsGKNXSSntVGMgxAeNjEP2cfGNzcB23NwXvxGONL8BSHf8wShGJ09t7A3rXhr2k313KedQsKvDowj13LSYlUGogoF+5RGPdLtpLxk6GntlucvhO+OPd+Ccyvzd/ESaVQeqep2tr9kET80jOtxjdr7Gbz4Hn2bDDM+l+qpswVKw6NgTWFJrLt1CH2VHqoaTsQoQjMuoqH6ZRb3TsrzXwJXNxWE9Nov8jf0qUFXRqXaghqhYBHFNaHrwMwOneQ+h+via8cVcDsmmrdHEsZijWmp9cfb+lcDIl5ZEg05EGGULnyHxeB8dp3LBYAVCLj6KthYGh4n8dHwd6HvfCDYYJQbwvV+I79TDUNc6PP32sbfLomLahCJbtRV+L+VKjp9wNbupF2rYVpijiz1cyATn43DPDkDnTS2eQbA+u0hUC32YqK3OmPiJk7pWp8uqGt15P0Rfyyb4ZJO7YhA+oghyRXB0IlQZ9DMlqbDF3g2mgghvSGw0HXoVcGElGLtaXIHh4Bbch3NxD/euc41YA4CwvpeTkoUg37dFI3Msl+4smeKiVIVtnL7ptOxmiJYhrZZSEDbjVLqvbuUaqn+sHMnn2TksNs6mbwgTTEpEBtf4FJ4kij1cg/UkPPLmyM9O5iDrCdNxYmhUM47wC1trFGeG4eKhYFKpIclBfZA+w2PEw7kZS8rr8jbBgzLiqVhRvUa0dHq4zgmnjR7baa0ED69kXXwx3O8I9JMECECjma7o75987fJFvhRaRhJpBl9Qlrb/8HRK97vwuMZEDU+uT5Rg7rfG1qiyUxxcMplvaAs5NxZy14BpD6oCeE912Iw+kflckGHRKvHpKJij9eRdhfesXSA3fwCILVqQAi0H0xclLdA2ieH2NyrYXsJPJvrh2NYSv+wzRSnFVjGGqhePwSniSUVoJRrkb9YVAKGmA7/2Vs4H8HGTgw3tM5RM50L0ObRYmH6epPFNfr9qipjxet11mn25Sa3dIbVkaF6Tl5bU6C0Ys3WXYIzVOa7PQAyLhjU7M7OeLY5kZK1DVLjApvUtb1PuQ83AcxhRctVCM1S6EwH6DWMC8hh5m2ysiqiBpmLUaPxUcMPPlK8/DP4X+ElaALnjUHXYx8l/LYvo8nbiwXB26Pt+h21CmSMpjeC2Dxk67HkCnLwm3WGztcnTyWjkz6zkf9YrxSG7Ql/wzGB4jANBgkrBgEEAYI3EQIxADATBgkqhkiG9w0BCRUxBgQEAQAAADBdBgkqhkiG9w0BCRQxUB5OAHQAZQAtAGMANgBiAGQAYQA2ADIAMgAtADMAMABhADQALQA0AGUAYwBiAC0AYQA4ADQANAAtADEAOQBjAGMAYgBmADEAMgBhADUAMQAxMF0GCSsGAQQBgjcRATFQHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQByAGUAIABLAGUAeQAgAFMAdABvAHIAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIwggQiBgkqhkiG9w0BBwagggQTMIIEDwIBADCCBAgGCSqGSIb3DQEHATBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQINoqHIcmRiwUCAgfQMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBswaO5+BydNdATUst6dpBMgIIDoDTTSNRlGrm+8N5VeKuaySe7dWmjL3W9baJNErXB7audUdapdWXsBYVgrHNMfYCOArbDesWQLE3JQILaQ7iQYYWqFk4qApKCjHyISJ6Ks9t46EcRRBx2RhE0eAVyoEBdsncYSSUeBmC6qvJfyXk6zL8F6XQ9Q6Gq/P9o9L+Bb2Z6IZurIFPolntimemAdD2XhPAYtk6MP2CeOTsBJHNAJ5Z2Je2F4nEknE+i48mmr/PPCA6k24vXNwXSyF7CKyQCa9dBnNjEo6M8p39UIlBvBWmleKq+GmkaZpEtG16aMFDaWSNgcifHk0xaT8aV4VToGl4fvXn1ZEPeGerN+4SbdDipMXZCmw5YpCBZYWi9qXuof8Ue6hnH48fQKHAVslNtSbS3FcnQavv7YTeR2Npf9lBZHhhnvoAVFCYOQH5CMBqqKiBVWJzBxF2evB1gKvzJnqqb6gJp62eH4NisThu06Gxd9LssVbri1z1600XequI2gcYpPPDY3IuUY8xGjfHvhFCcIegkp3oQfUg+G7GHjQgiwZqnV1tmk76wamreYh/3zX4lZlpQbpFpUz+MB4WPFoTeHm2/IRhs2Dur6nMQEidd/UstLH83pJNcQO0e/DHUGt8FIyeMcfox6V/ml3mqx50StY9b68+TIFk6htZkHXAzer8c0HF00R6L/XdUfd9BkffngNX4Ca+cmrAQN44j7/lGJSrEbTYbxxLTiwOTm7fMddBdI9Y49O3wy5lvrH+TMdMIJCRG2oOCILGQZkRzzgznixo12tjgjW5CSmjRKdnLlZl47cGEJDmB7gFS7WB7i/qot23sFSvunnivvx7mVYrsItAIdPFXzzV/WS2Go+1eJMW0GOhA7EN4R0TnFp0WjPZjR4QNU0q034C2v9wldGlK+EVJaRnAZqlpJ0khfOz12LSDm90JgHIUi3eQxL6dOuwLwbiz5/aBhCGitZVGq4gRcaIPTfWniqv3QoyA+i3k/Nn2IEAi8a7R9DPlmkvQaAvKAkaO53c7XzOj0hTnkjO7PfhiwGgpCFdHlKg5jk/SB6qxkSwtXZwKaUIynnlu52PykemOh/+OZ+e6p8CiBv9my650avE0teCE9csOjOAQL7BCKHIC6XpsSLUuHhz7cTf8MehzJRSgkl5lmdW8+wJmOPmoRznUe5lvKT6x7op6OqiBjVKcl0QLMhvkJBY4TczbrRRA97G96BHN4DBJpg4kCM/votw4eHQPrhPVce0wSzAvMAsGCWCGSAFlAwQCAQQgj1Iu53yHiWVEMsvWiRSzVpPEeNzjeXXdrfuUMhBDWAQEFLYa3qh/1OH1CugDTUZD8yt4lOIFAgIH0A==`
    p12, _ := base64.StdEncoding.DecodeString(base64P12)
    pk, cert, caCerts, err := DecodeChain(p12, "password")
    if err != nil {
        t.Fatal(err)
    }

    rsaPk, ok := pk.(*rsa.PrivateKey)
    if !ok {
        t.Error("could not cast to rsa private key")
    }
    if !rsaPk.PublicKey.Equal(cert.PublicKey) {
        t.Error("public key embedded in private key not equal to public key of certificate")
    }
    if cert.Subject.CommonName != commonName {
        t.Errorf("unexpected leaf cert common name, got %s, want %s", cert.Subject.CommonName, commonName)
    }
    if len(caCerts) != 0 {
        t.Errorf("unexpected # of caCerts: got %d, want 0", len(caCerts))
    }
}

func TestPBES2_AES128CBC(t *testing.T) {
    // PKCS7 Encrypted data: PBES2, PBKDF2, AES-128-CBC, Iteration 2048, PRF hmacWithSHA256
    commonName := "example-com"
    base64P12 := `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`

    p12, _ := base64.StdEncoding.DecodeString(base64P12)
    pk, cert, caCerts, err := DecodeChain(p12, "rHyQTJsubhfxcpH5JttyilHE6BBsNoZp")
    if err != nil {
        t.Fatal(err)
    }

    rsaPk, ok := pk.(*rsa.PrivateKey)
    if !ok {
        t.Error("could not cast to rsa private key")
    }

    if !rsaPk.PublicKey.Equal(cert.PublicKey) {
        t.Error("public key embedded in private key not equal to public key of certificate")
    }
    if cert.Subject.CommonName != commonName {
        t.Errorf("unexpected leaf cert common name, got %s, want %s", cert.Subject.CommonName, commonName)
    }
    if len(caCerts) != 0 {
        t.Errorf("unexpected # of caCerts: got %d, want 0", len(caCerts))
    }
}

// Valid PKCS #12 File with SHA-256 HMAC and PRF
var testPBMAC1Pfx_1 = `
-----BEGIN Data-----
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
3QQITk9UIFVTRUQCAQE=
-----END Data-----
`

// Valid PKCS #12 File with SHA-256 HMAC and SHA-512 PRF
var testPBMAC1Pfx_2 = `
-----BEGIN Data-----
MIIKigIBAzCCCgUGCSqGSIb3DQEHAaCCCfYEggnyMIIJ7jCCBGIGCSqGSIb3DQEH
BqCCBFMwggRPAgEAMIIESAYJKoZIhvcNAQcBMFcGCSqGSIb3DQEFDTBKMCkGCSqG
SIb3DQEFDDAcBAi4j6UBBY2iOgICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQME
ASoEEFpHSS5zrk/9pkDo1JRbtE6AggPgtbMLGoFd5KLpVXMdcxLrT129L7/vCr0B
0I2tnhPPA7aFtRjjuGbwooCMQwxw9qzuCX1eH4xK2LUw6Gbd2H47WimSOWJMaiUb
wy4alIWELYufe74kXPmKPCyH92lN1hqu8s0EGhIl7nBhWbFzow1+qpIc9/lpujJo
wodSY+pNBD8oBeoU1m6DgOjgc62apL7m0nwavDUqEt7HAqtTBxKxu/3lpb1q8nbl
XLTqROax5feXErf+GQAqs24hUJIPg3O1eCMDVzH0h5pgZyRN9ZSIP0HC1i+d1lnb
JwHyrAhZv8GMdAVKaXHETbq8zTpxT3UE/LmH1gyZGOG2B21D2dvNDKa712sHOS/t
3XkFngHDLx+a9pVftt6p7Nh6jqI581tb7fyc7HBV9VUc/+xGgPgHZouaZw+I3PUz
fjHboyLQer22ndBz+l1/S2GhhZ4xLXg4l0ozkgn7DX92S/UlbmcZam1apjGwkGY/
7ktA8BarNW211mJF+Z+hci+BeDiM7eyEguLCYRdH+/UBiUuYjG1hi5Ki3+42pRZD
FZkTHGOrcG6qE2KJDsENj+RkGiylG98v7flm4iWFVAB78AlAogT38Bod40evR7Ok
c48sOIW05eCH/GLSO0MHKcttYUQNMqIDiG1TLzP1czFghhG97AxiTzYkKLx2cYfs
pgg5PE9drq1fNzBZMUmC2bSwRhGRb5PDu6meD8uqvjxoIIZQAEV53xmD63umlUH1
jhVXfcWSmhU/+vV/IWStZgQbwhF7DmH2q6S8itCkz7J7Byp5xcDiUOZ5Gpf9RJnk
DTZoOYM5iA8kte6KCwA+jnmCgstI5EbRbnsNcjNvAT3q/X776VdmnehW0VeL+6k4
z+GvQkr+D2sxPpldIb5hrb+1rcp9nOQgtpBnbXaT16Lc1HdTNe5kx4ScujXOWwfd
Iy6bR6H0QFq2SLKAAC0qw4E8h1j3WPxll9e0FXNtoRKdsRuX3jzyqDBrQ6oGskkL
wnyMtVjSX+3c9xbFc4vyJPFMPwb3Ng3syjUDrOpU5RxaMEAWt4josadWKEeyIC2F
wrS1dzFn/5wv1g7E7xWq+nLq4zdppsyYOljzNUbhOEtJ2lhme3NJ45fxnxXmrPku
gBda1lLf29inVuzuTjwtLjQwGk+usHJm9R/K0hTaSNRgepXnjY0cIgS+0gEY1/BW
k3+Y4GE2JXds2cQToe5rCSYH3QG0QTyUAGvwX6hAlhrRRgUG3vxtYSixQ3UUuwzs
eQW2SUFLl1611lJ7cQwFSPyr0sL0p81vdxWiigwjkfPtgljZ2QpmzR5rX2xiqItH
Dy4E+iVigIYwggWEBgkqhkiG9w0BBwGgggV1BIIFcTCCBW0wggVpBgsqhkiG9w0B
DAoBAqCCBTEwggUtMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAhDiwsh
4wt3aAICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEELNFnEpJT65wsXwd
fZ1g56cEggTQRo04bP/fWfPPZrTEczq1qO1HHV86j76Sgxau2WQ9OQAG998HFtNq
NxO8R66en6QFhqpWCI73tSJD+oA29qOsT+Xt2bR2z5+K7D4QoiXuLa3gXv62VkjB
0DLCHAS7Mu+hkp5OKCpXCS7fo0OnAiQjM4EluAsiwwLrHu7z1E16UwpmlgKQnaC1
S44fV9znS9TxofRTnuCq1lupdn2qQjSydOU6inQeKLBflKRiLrJHOobaFmjWwp1U
OQAMuZrALhHyIbOFXMPYk3mmU/1UPuRGcbcV5v2Ut2UME+WYExXSCOYR3/R4UfVk
IfEzeRPFs2slJMIDS2fmMyFkEEElBckhKO9IzhQV3koeKUBdM066ufyax/uIyXPm
MiB9fAqbQQ4jkQTT80bKkBAP1Bvyg2L8BssstR5iCoZgWnfA9Uz4RI5GbRqbCz7H
iSkuOIowEqOox3IWbXty5VdWBXNjZBHpbE0CyMLSH/4QdGVw8R0DiCAC0mmaMaZq
32yrBR32E472N+2KaicvX31MwB/LkZN46c34TGanL5LJZx0DR6ITjdNgP8TlSSrp
7y2mqi7VbKp/C/28Cj5r+m++Gk6EOUpLHsZ2d2hthrr7xqoPzUAEkkyYWedHJaoQ
TkoIisZb0MGlXb9thjQ8Ee429ekfjv7CQfSDS6KTE/+mhuJ33mPz1ZcIacHjdHhE
6rbrKhjSrLbgmrGa8i7ezd89T4EONu0wkG9KW0wM2cn5Gb12PF6rxjTfzypG7a50
yc1IJ2Wrm0B7gGuYpVoCeIohr7IlxPYdeQGRO/SlzTd0xYaJVm9FzJaMNK0ZqnZo
QMEPaeq8PC3kMjpa8eAiHXk9K3DWdOWYviGVCPVYIZK6Cpwe+EwfXs+2hZgZlYzc
vpUWg60md1PD4UsyLQagaj37ubR6K4C4mzlhFx5NovV/C/KD+LgekMbjCtwEQeWy
agev2l9KUEz73/BT4TgQFM5K2qZpVamwmsOmldPpekGPiUCu5YxYg/y4jUKvAqj1
S9t4wUAScCJx8OvXUfgpmS2+mhFPBiFps0M4O3nWG91Q6mKMqbNHPUcFDn9P7cUh
s1xu3NRLyJ+QIfVfba3YBTV8A6WBYEmL9lxf1uL1WS2Bx6+Crh0keyNUPo9cRjpx
1oj/xkInoc2HQODEkvuK9DD7VrLr7sDhfmJvr1mUfJMQ5/THk7Z+E+NAuMdMtkM2
yKXxghZAbBrQkU3mIW150i7PsjlUw0o0/LJvQwJIsh6yeJDHY8mby9mIdeP3LQAF
clYKzNwmgwbdtmVAXmQxLuhmEpXfstIzkBrNJzChzb2onNSfa+r5L6XEHNHl7wCw
TuuV/JWldNuYXLfVfuv3msfSjSWkv6aRtRWIvmOv0Qba2o05LlwFMd1PzKM5uN4D
DYtsS9A6yQOXEsvUkWcLOJnCs8SkJRdXhJTxdmzeBqM1JttKwLbgGMbpjbxlg3ns
N+Z+sEFox+2ZWOglgnBHj0mCZOiAC8wqUu+sxsLT4WndaPWKVqoRQChvDaZaNOaN
qHciF9HPUcfZow+fH8TnSHneiQcDe6XcMhSaQ2MtpY8/jrgNKguZt22yH9gw/VpT
3/QOB7FBgKFIEbvUaf3nVjFIlryIheg+LeiBd2isoMNNXaBwcg2YXukxJTAjBgkq
hkiG9w0BCRUxFgQUwWO5DorvVWYF3BWUmAw0rUEajScwfDBtMEkGCSqGSIb3DQEF
DjA8MCwGCSqGSIb3DQEFDDAfBAgUr2yP+/DBrgICCAACASAwDAYIKoZIhvcNAgsF
ADAMBggqhkiG9w0CCQUABCA5zFL93jw8ItGlcbHKhqkNwbgpp6layuOuxSju4/Vd
6QQITk9UIFVTRUQCAQE=
-----END Data-----
`

// Valid PKCS #12 File with SHA-512 HMAC and PRF
var testPBMAC1Pfx_3 = `
-----BEGIN Data-----
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
-----END Data-----
`

func Test_PBMAC1Pfx_Check(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    t.Run("PBMAC1Pfx 1", func(t *testing.T) {
        pfxData := decodePEM(testPBMAC1Pfx_1)

        password := "1234"

        privateKey, certificate, err := Decode(pfxData, password)
        assertNotEmpty(privateKey, "Test_PBMAC1Pfx_Check-pfxData")
        assertNotEmpty(certificate, "Test_PBMAC1Pfx_Check-pfxData")
        assertError(err, "Test_PBMAC1Pfx_Check-pfxData")
    })

    t.Run("PBMAC1Pfx 2", func(t *testing.T) {
        pfxData := decodePEM(testPBMAC1Pfx_2)

        password := "1234"

        privateKey, certificate, err := Decode(pfxData, password)
        assertNotEmpty(privateKey, "Test_PBMAC1Pfx_Check-pfxData")
        assertNotEmpty(certificate, "Test_PBMAC1Pfx_Check-pfxData")
        assertError(err, "Test_PBMAC1Pfx_Check-pfxData")
    })

    t.Run("PBMAC1Pfx 3", func(t *testing.T) {
        pfxData := decodePEM(testPBMAC1Pfx_3)

        password := "1234"

        privateKey, certificate, err := Decode(pfxData, password)
        assertNotEmpty(privateKey, "Test_PBMAC1Pfx_Check-pfxData")
        assertNotEmpty(certificate, "Test_PBMAC1Pfx_Check-pfxData")
        assertError(err, "Test_PBMAC1Pfx_Check-pfxData")
    })
}

// ======================

/*
$ openssl pkcs12 \
    -export \
    -in cert.pem \
    -inkey private-key.pem \
    -password "pass:abc" \
    -iter 200000 \
    -macalg sha256 \
    -macsaltlen 32 \
    -out certbagSHA256.p12
*/

var testMD5Pfx_Encode = `
-----BEGIN Data-----
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
-----END Data-----
`
var testSHA1Pfx_Encode = `
-----BEGIN Data-----
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
-----END Data-----
`
var testSHA224Pfx_Encode = `
-----BEGIN Data-----
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
qW+sKIUCAwMNQA==
-----END Data-----
`
var testSHA256Pfx_Encode = `
-----BEGIN Cert-----
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
CDulZdoGGygLAgMDDUA=
-----END Cert-----
`
var testSHA384Pfx_Encode = `
-----BEGIN Data-----
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
-----END Data-----
`
var testSHA512Pfx_Encode = `
-----BEGIN Data-----
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
-----END Data-----
`
var testSM3Pfx_Encode = `
-----BEGIN Data-----
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
GeGYxiK9xO0CAwMNQA==
-----END Data-----
`

func Test_NewPfx_Check(t *testing.T) {
    t.Run("MD5", func(t *testing.T) {
        test_NewPfx_Check(t, testMD5Pfx_Encode)
    })
    t.Run("SHA1", func(t *testing.T) {
        test_NewPfx_Check(t, testSHA1Pfx_Encode)
    })
    t.Run("SHA224", func(t *testing.T) {
        test_NewPfx_Check(t, testSHA224Pfx_Encode)
    })
    t.Run("SHA256", func(t *testing.T) {
        test_NewPfx_Check(t, testSHA256Pfx_Encode)
    })
    t.Run("SHA384", func(t *testing.T) {
        test_NewPfx_Check(t, testSHA384Pfx_Encode)
    })
    t.Run("SHA512", func(t *testing.T) {
        test_NewPfx_Check(t, testSHA512Pfx_Encode)
    })
    t.Run("SM3", func(t *testing.T) {
        test_NewPfx_Check(t, testSM3Pfx_Encode)
    })
}

func test_NewPfx_Check(t *testing.T, pfx string) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    pfxData := decodePEM(pfx)

    password := "abc"

    privateKey, certificate, err := Decode(pfxData, password)
    assertNotEmpty(privateKey, "Test_NewPfx_Check-pfxData")
    assertNotEmpty(certificate, "Test_NewPfx_Check-pfxData")
    assertError(err, "Test_NewPfx_Check-pfxData")
}
