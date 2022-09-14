### pkcs12 使用文档

* pkcs12 生成及解析
~~~go
package main

import (
    "fmt"
    "errors"
    "crypto/rsa"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"

    "github.com/deatil/lakego-filesystem/filesystem"

    cryptobin_rsa "github.com/deatil/go-cryptobin/cryptobin/rsa"
    cryptobin_pkcs12 "github.com/deatil/go-cryptobin/pkcs12"
)

func main() {
    MakePKCS12()

    fmt.Println("运行成功")
}

func MakePKCS12() error {
    fs := filesystem.New()

    path := "./runtime/key/pkcs12/ca/%s"

    caCertFile := fmt.Sprintf(path, "caCert.cer")
    certificateFile := fmt.Sprintf(path, "certificate.cer")
    privateKeyFile := fmt.Sprintf(path, "private.key")

    caCertData, _ := fs.Get(caCertFile)
    certificateData, _ := fs.Get(certificateFile)
    privateKeyData, _ := fs.Get(privateKeyFile)

    // Parse PEM block
    var caCertBlock *pem.Block
    if caCertBlock, _ = pem.Decode([]byte(caCertData)); caCertBlock == nil {
        return errors.New("caCert err")
    }

    caCerts, err := x509.ParseCertificates(caCertBlock.Bytes)
    if err != nil {
        return err
    }

    // Parse PEM block
    var certificateBlock *pem.Block
    if certificateBlock, _ = pem.Decode([]byte(certificateData)); certificateBlock == nil {
        return errors.New("certificate err")
    }

    certificates, err := x509.ParseCertificates(certificateBlock.Bytes)
    if err != nil {
        return err
    }

    privateKey := cryptobin_rsa.NewRsa().
        FromPrivateKey([]byte(privateKeyData)).
        GetPrivateKey()

    // [Encode] 兼容官方库
    // pfxData, err := cryptobin_pkcs12.Encode(rand.Reader, privateKey, certificates[0], "123")
    // pfxData, err := cryptobin_pkcs12.EncodeChain(rand.Reader, privateKey, certificates[0], caCerts, "123")
    pfxData, err := cryptobin_pkcs12.EncodeChain(rand.Reader, privateKey, certificates[0], caCerts, "123", cryptobin_pkcs12.Opts{
        PKCS8Cipher: cryptobin_pkcs12.GetPKCS8PbeCipherFromName("SHA1AndRC2_40"),
        Cipher: cryptobin_pkcs12.CipherSHA1AndRC2_40,
        KDFOpts: cryptobin_pkcs12.MacOpts{
            SaltSize: 8,
            IterationCount: 1,
            HMACHash: cryptobin_pkcs12.SHA1,
        },
    })
    if err != nil {
        return err
    }

    pkcs12File := fmt.Sprintf(path, "pkcs12.p12")
    fs.Put(pkcs12File, string(pfxData))

    // 保存为 pem 证书
    pkcs12Blocks, err := cryptobin_pkcs12.ToPEM(pfxData, "123")
    if err != nil {
        return err
    }

    for k, block := range pkcs12Blocks {
        pkcs12BlockKeyData := pem.EncodeToMemory(block)

        pkcs12BlockFile := fmt.Sprintf(path, fmt.Sprintf("pkcs12-block-%d.key", k))
        fs.Put(pkcs12BlockFile, string(pkcs12BlockKeyData))
    }

    // EncodeTrustStore
    pfxDataTrustStore, err := cryptobin_pkcs12.EncodeTrustStore(rand.Reader, certificates, "123")
    if err != nil {
        return err
    }

    pkcs12FileTrustStore := fmt.Sprintf(path, "pkcs12-TrustStore.p12")
    fs.Put(pkcs12FileTrustStore, string(pfxDataTrustStore))

    // 解析测试
    p12, _ := fs.Get(pkcs12File)
    // priv, cert, err := cryptobin_pkcs12.Decode([]byte(p12), "123")
    priv, cert, caCerts, err := cryptobin_pkcs12.DecodeChain([]byte(p12), "123")
    if err != nil {
        fmt.Println("err =====")
        fmt.Println(err.Error())
        fmt.Println("")
    }

    fmt.Println("priv =====")
    fmt.Printf("%#v", priv)
    fmt.Println("")

    fmt.Println("cert =====")
    fmt.Printf("%#v", cert)
    fmt.Println("")

    fmt.Println("caCerts =====")
    fmt.Printf("%#v", caCerts)
    fmt.Println("")

    // 解析测试 DecodeTrustStore
    p12TrustStore, _ := fs.Get(pkcs12FileTrustStore)
    certs, err := cryptobin_pkcs12.DecodeTrustStore([]byte(p12TrustStore), "123")
    if err != nil {
        fmt.Println("TrustStore err =====")
        fmt.Println(err.Error())
        fmt.Println("")
    }

    fmt.Println("TrustStore certs =====")
    fmt.Printf("%#v", certs[0])
    fmt.Println("")

    return nil
}
~~~
