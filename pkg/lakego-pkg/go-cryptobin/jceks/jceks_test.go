package jceks

import (
    "fmt"
    "testing"
    "io/ioutil"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func testMustReadFile(tb testing.TB, filename string) []byte {
    tb.Helper()

    b, err := ioutil.ReadFile(filename)
    if err != nil {
        tb.Fatal(err)
    }

    return b
}

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

func Test_JksEncode(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    caCerts, err := x509.ParseCertificates(decodePEM(caCert))
    assertError(err, "JksEncode-caCerts")

    cert, err := x509.ParseCertificate(decodePEM(certificate))
    assertError(err, "JksEncode-cert")

    parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
    assertError(err, "JksEncode-privateKey")

    privateKey, ok := parsedKey.(*rsa.PrivateKey)
    if !ok {
        t.Error("JksEncode rsa Error")
    }

    en := NewJksEncode()
    en.AddPrivateKey("priv-test", privateKey, "test", caCerts) // 私钥和证书链
    en.AddTrustedCert("cert-test", cert) // 证书
    pfxData, err := en.Marshal("test-pwd")

    assertError(err, "JksEncode Marshal Error")
    assertNotEmpty(pfxData, "JksEncode-pfxData")

    // ========

    ks, err := LoadJksFromBytes(pfxData, "test-pwd")
    assertError(err, "JksEncode-DE")

    priAliases := ks.ListPrivateKeys()
    assertNotEmpty(priAliases, "JksEncode-ListPrivateKeys")

    certsAliases := ks.ListCerts()
    assertNotEmpty(certsAliases, "JksEncode-ListCerts")

    key, err := ks.GetPrivateKey("priv-test", "test")
    assertError(err, "JksEncode-GetPrivateKey")
    assertNotEmpty(key, "JksEncode-GetPrivateKey")
    assertEqual(key, privateKey, "JksEncode-GetPrivateKey")

    certs, err := ks.GetCertChain("priv-test")
    assertError(err, "JksEncode-GetCertChain")
    assertNotEmpty(certs, "JksEncode-GetCertChain")
    assertEqual(certs, caCerts, "JksEncode-GetCertChain")

    cert2, err := ks.GetCert("cert-test")
    assertError(err, "JksEncode-GetCert")
    assertNotEmpty(cert2, "JksEncode-GetCert")
    assertEqual(cert2, cert, "JksEncode-GetCert")

}

func Test_JceksEncode(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    caCerts, err := x509.ParseCertificates(decodePEM(caCert))
    assertError(err, "JceksEncode-caCerts")

    cert, err := x509.ParseCertificate(decodePEM(certificate))
    assertError(err, "JceksEncode-cert")

    parsedKey, err := x509.ParsePKCS8PrivateKey(decodePEM(privateKey))
    assertError(err, "JceksEncode-privateKey")

    privateKey, ok := parsedKey.(*rsa.PrivateKey)
    if !ok {
        t.Error("JceksEncode rsa Error")
    }

    secretKey := []byte("test-pass")

    en := NewJceksEncode()
    en.AddPrivateKey("priv-test", privateKey, "test", caCerts) // 私钥和证书链
    en.AddTrustedCert("cert-test", cert) // 证书
    en.AddSecretKey("secret-test", secretKey, "test-pass") // 密钥
    pfxData, err := en.Marshal("test-pwd")

    assertError(err, "JceksEncode Marshal Error")
    assertNotEmpty(pfxData, "JceksEncode-pfxData")

    // ========

    ks, err := LoadFromBytes(pfxData, "test-pwd")
    assertError(err, "JceksEncode-DE")

    priAliases := ks.ListPrivateKeys()
    assertNotEmpty(priAliases, "JceksEncode-ListPrivateKeys")

    certsAliases := ks.ListCerts()
    assertNotEmpty(certsAliases, "JceksEncode-ListCerts")

    secretsAliases := ks.ListSecretKeys()
    assertNotEmpty(secretsAliases, "JceksEncode-ListSecretKeys")

    key, certs, err := ks.GetPrivateKeyAndCerts("priv-test", "test")
    assertError(err, "JceksEncode-GetPrivateKeyAndCerts")

    assertNotEmpty(key, "JceksEncode-GetPrivateKeyAndCerts")
    assertEqual(key, privateKey, "JceksEncode-GetPrivateKeyAndCerts")

    assertNotEmpty(certs, "JceksEncode-GetPrivateKeyAndCerts")
    assertEqual(certs, caCerts, "JceksEncode-GetPrivateKeyAndCerts")

    cert2, err := ks.GetCert("cert-test")
    assertError(err, "JceksEncode-GetCert")
    assertNotEmpty(cert2, "JceksEncode-GetCert")
    assertEqual(cert2, cert, "JceksEncode-GetCert")

    secret, err := ks.GetSecretKey("secret-test", "test-pass")
    assertError(err, "JceksEncode-GetSecretKey")
    assertNotEmpty(secret, "JceksEncode-GetSecretKey")
    assertEqual(secret, secretKey, "JceksEncode-GetSecretKey")

}

// ========

func Test_Jceks_Check(t *testing.T) {
    test_Jceks_Check(t, testMustReadFile(t, "testdata/jceks/example-custom-oid.jceks"), "password", 1)
    test_Jceks_Check(t, testMustReadFile(t, "testdata/jceks/example-elliptic-sha1.jceks"), "password", 1)
    test_Jceks_Check(t, testMustReadFile(t, "testdata/jceks/example-sha1.jceks"), "password", 1)
    test_Jceks_Check(t, testMustReadFile(t, "testdata/jceks/example-root.jceks"), "password", 1)
    test_Jceks_Check(t, testMustReadFile(t, "testdata/jceks/example-small-key.jceks"), "password", 1)
}

func test_Jceks_Check(t *testing.T, data []byte, pass string, num int) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    ks, err := LoadFromBytes(data, pass)
    if err != nil {
        t.Fatal(err)
    }

    if num == 1 {
        priAliases := ks.ListPrivateKeys()
        assertNotEmpty(priAliases, "Jceks_Check-ListPrivateKeys")
    }

    if num == 2 {
        certsAliases := ks.ListCerts()
        assertNotEmpty(certsAliases, "Jceks_Check-ListCerts")
    }

    if num == 3 {
        secretsAliases := ks.ListSecretKeys()
        assertNotEmpty(secretsAliases, "Jceks_Check-ListSecretKeys")
    }

}

func Test_Jks_Check(t *testing.T) {
    test_Jks_Check(t, testMustReadFile(t, "testdata/jks/diff_pass.jks"), "password1", 1)
    test_Jks_Check(t, testMustReadFile(t, "testdata/jks/DSA_1024_keystore.jks"), "password", 1)
    test_Jks_Check(t, testMustReadFile(t, "testdata/jks/EC_256_keystore.jks"), "password", 1)
    test_Jks_Check(t, testMustReadFile(t, "testdata/jks/RSA_2048_keystore.jks"), "password", 1)
    test_Jks_Check(t, testMustReadFile(t, "testdata/jks/RSA_2048_truststore.jks"), "password", 2)
    test_Jks_Check(t, testMustReadFile(t, "testdata/jks/RSA_2048_MD5withRSA_keystore.jks"), "password", 1)

    test_Jks_Check(t, testMustReadFile(t, "testdata/jks/androidstudio_default_123456_myalias.jks"), "123456", 1)
    test_Jks_Check(t, testMustReadFile(t, "testdata/jks/windows_defaults_123456_mykey.jks"), "123456", 1)
}

func test_Jks_Check(t *testing.T, data []byte, pass string, num int) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    ks, err := LoadJksFromBytes(data, pass)
    if err != nil {
        t.Fatal(err)
    }

    if num == 1 {
        priAliases := ks.ListPrivateKeys()
        assertNotEmpty(priAliases, fmt.Sprintf("[%d] Jks_Check-ListPrivateKeys", num))
    }

    if num == 2 {
        certsAliases := ks.ListCerts()
        assertNotEmpty(certsAliases, fmt.Sprintf("[%d] Jks_Check-ListCerts", num))
    }

}

func Test_Bks_Check(t *testing.T) {
    test_Bks_Check(t, testMustReadFile(t, "testdata/bks/christmas.bksv1"), "12345678", 1)
    test_Bks_Check(t, testMustReadFile(t, "testdata/bks/christmas.bksv2"), "12345678", 1)

    test_Bks_Check(t, testMustReadFile(t, "testdata/bks/custom_entry_passwords.bksv1"), "store_password", 5)
    test_Bks_Check(t, testMustReadFile(t, "testdata/bks/custom_entry_passwords.bksv2"), "store_password", 5)

    test_Bks_Check(t, testMustReadFile(t, "testdata/bks/empty.bksv1"), "", 6)
    test_Bks_Check(t, testMustReadFile(t, "testdata/bks/empty.bksv2"), "", 6)
}

func test_Bks_Check(t *testing.T, data []byte, pass string, num int) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    ks, err := LoadBksFromBytes(data, pass)
    if err != nil {
        t.Fatal(err)
    }

    if num == 1 {
        priAliases := ks.ListKeys()
        assertNotEmpty(priAliases, fmt.Sprintf("[%d] Jks_Check-ListKeys", num))
    }

    if num == 2 {
        certsAliases := ks.ListSecrets()
        assertNotEmpty(certsAliases, fmt.Sprintf("[%d] Jks_Check-ListSecrets", num))
    }

    if num == 3 {
        certsAliases := ks.ListCerts()
        assertNotEmpty(certsAliases, fmt.Sprintf("[%d] Jks_Check-ListCerts", num))
    }

    if num == 5 {
        certsAliases := ks.ListSealedKeys()
        assertNotEmpty(certsAliases, fmt.Sprintf("[%d] Jks_Check-ListSealedKeys", num))
    }

}

func Test_Uber_Check(t *testing.T) {
    test_Uber_Check(t, testMustReadFile(t, "testdata/uber/christmas.uber"), "12345678", 1)
    test_Uber_Check(t, testMustReadFile(t, "testdata/uber/custom_entry_passwords.uber"), "store_password", 5)
    test_Uber_Check(t, testMustReadFile(t, "testdata/uber/empty.uber"), "", 6)
}

func test_Uber_Check(t *testing.T, data []byte, pass string, num int) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    ks, err := LoadUberFromBytes(data, pass)
    if err != nil {
        t.Fatal(err)
    }

    if num == 1 {
        priAliases := ks.ListKeys()
        assertNotEmpty(priAliases, fmt.Sprintf("[%d] Jks_Check-ListKeys", num))
    }

    if num == 2 {
        certsAliases := ks.ListSecrets()
        assertNotEmpty(certsAliases, fmt.Sprintf("[%d] Jks_Check-ListSecrets", num))
    }

    if num == 3 {
        certsAliases := ks.ListCerts()
        assertNotEmpty(certsAliases, fmt.Sprintf("[%d] Jks_Check-ListCerts", num))
    }

    if num == 5 {
        certsAliases := ks.ListSealedKeys()
        assertNotEmpty(certsAliases, fmt.Sprintf("[%d] Jks_Check-ListSealedKeys", num))
    }

}
