### PKCS12 使用文档

* 解析证书

~~~go
package main

import (
    "fmt"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs12"
)

func decodePEM(pubPEM string) []byte {
    block, _ := pem.Decode([]byte(pubPEM))
    if block == nil {
        panic("failed to parse PEM block containing the key")
    }

    return block.Bytes
}

// PEM 格式证书
var testPfxPEM = `
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
`

func main() {
    // 解码 PEM 证书
    pfxData := decodePEM(testPfxPEM)

    // 密码
    password := "pass"

    // 解析证书
    // priv, cert, caCerts, err := pkcs12.DecodeChain(pfxData, password)
    privateKey, certificate, err := pkcs12.Decode(pfxData, password)
    if err != nil {
        fmt.Println("解析失败")
        return
    }

    fmt.Println("解析成功")
}
~~~

* pkcs12 生成

~~~go
package main

import (
    "fmt"
    "crypto"
    "crypto/rand"
    "crypto/x509"

    "github.com/deatil/go-cryptobin/pkcs12"
)

func main() {
    err := makePKCS12()
    if err != nil {
        fmt.Println("编码失败")
        return
    }

    fmt.Println("编码成功")
}

// 生成证书
func makePKCS12() error {
    var privateKey crypto.PrivateKey = ...
    var certificates []*x509.Certificate = ...
    var caCerts []*x509.Certificate = ...

    // 密码
    var password string = "123"

    // [Encode] 兼容官方库
    // pfxData, err := pkcs12.Encode(rand.Reader, privateKey, certificates[0], password)
    // pfxData, err := pkcs12.EncodeChain(rand.Reader, privateKey, certificates[0], caCerts, password)
    pfxData, err := pkcs12.EncodeChain(rand.Reader, privateKey, certificates[0], caCerts, password, pkcs12.Opts{
        KeyCipher: pkcs12.GetPbes1CipherFromName("SHA1AndRC2_40"),
        CertCipher: pkcs12.CipherSHA1AndRC2_40,
        CertKDFOpts: pkcs12.MacOpts{
            SaltSize:       8,
            IterationCount: 1,
            HMACHash:       pkcs12.SHA1,
        },
    })
    if err != nil {
        return err
    }
    
    return nil
}

// 生成 TrustStore 证书
func makeEncodeTrustStore() error {
    var certificates []*x509.Certificate = ...

    // 密码
    var password string = "123"

    // EncodeTrustStore
    pfxDataTrustStore, err := pkcs12.EncodeTrustStore(rand.Reader, certificates, password)
    if err != nil {
        return err
    }
    
    return nil

}

// 自定义生成证书
func makePKCS12WithOpts() error {
    var privateKey crypto.PrivateKey = ...
    var certificates []*x509.Certificate = ...

    // 密码
    var password string = "123"

    pfxData, err := pkcs12.Encode(rand.Reader, privateKey, certificates[0], password, pkcs12.Opts{
        KeyCipher: pkcs12.GetPbes2CipherFromName("AES256CFB"),
        KeyKDFOpts: pkcs12.PBKDF2Opts{
            SaltSize:       16,
            IterationCount: 10000,
        },
        CertCipher: pkcs12.CipherSHA1AndRC2_40,
        CertKDFOpts: pkcs12.MacOpts{
            SaltSize:       8,
            IterationCount: 1024,
            HMACHash:       pkcs12.SHA512,
        },
    })
    if err != nil {
        return err
    }

    return nil
}

~~~
