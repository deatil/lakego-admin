### pkcs7 使用文档

* 使用
~~~go
package main

import (
    "os"
    "fmt"
    "bytes"
    "crypto/rsa"
    "crypto/x509"

    "github.com/deatil/go-cryptobin/pkcs7"
    "github.com/deatil/go-cryptobin/pkcs7/sign"
    "github.com/deatil/go-cryptobin/pkcs7/encrypt"
)

func SignAndDetach(content []byte, cert *x509.Certificate, privkey *rsa.PrivateKey) (signed []byte, err error) {
    toBeSigned, err := sign.NewSignedData(content)
    if err != nil {
        err = fmt.Errorf("Cannot initialize signed data: %s", err)
        return
    }
    if err = toBeSigned.AddSigner(cert, privkey, sign.SignerInfoConfig{}); err != nil {
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
    pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})

    p7, err := sign.Parse(signed)
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

    key := []byte("123456789012werfde1234567890rt32")
    // enData, err := encrypt.Encrypt(signed, []*x509.Certificate{cert})
    enData, err := encrypt.EncryptUsingPSK(signed, key, encrypt.AES256CBC)
    enDataw := pkcs7.EncodePkcs7ToPem(enData, "ENCRYPTED PKCS7")

    deData, _ := pkcs7.ParsePkcs7Pem(enDataw)
    // deDataw, err := encrypt.Decrypt(deData, cert, privkey)
    deDataw, err := encrypt.DecryptUsingPSK(deData, key)

    return deDataw, err
}

~~~

* SignAndDetach 使用
~~~go

    pkcs7Data := cryptobin_pkcs7.TestFixtureresult
    pkcs7Sign, pkcs7err := cryptobin_pkcs7.SignAndDetach([]byte("hello world"), pkcs7Data.Certificate, pkcs7Data.PrivateKey)
~~~

* 测试数据
~~~go
// pkg: cryptobin_pkcs7

package pkcs7

import (
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
)

var EncryptedTestCertificate = `-----BEGIN CERTIFICATE-----
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
var EncryptedTestPrivateKey = `-----BEGIN PRIVATE KEY-----
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

type TestFixture struct {
    Certificate *x509.Certificate
    PrivateKey  *rsa.PrivateKey
}

var TestFixtureresult TestFixture

func init() {
    derBlock1, _ := pem.Decode([]byte(EncryptedTestCertificate))
    derBlock2, _ := pem.Decode([]byte(EncryptedTestPrivateKey))

    TestFixtureresult.Certificate, _ = x509.ParseCertificate(derBlock1.Bytes)
    parsedKey, _ := x509.ParsePKCS8PrivateKey(derBlock2.Bytes)

    TestFixtureresult.PrivateKey, _ = parsedKey.(*rsa.PrivateKey)

}
~~~
