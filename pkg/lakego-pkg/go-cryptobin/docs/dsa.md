### DSA 使用说明

* 常规使用
~~~go
package main

import (
    "fmt"

    cryptobin "github.com/deatil/go-cryptobin/cryptobin/dsa"
    "github.com/deatil/lakego-filesystem/filesystem"
)

func main() {
    // 文件管理器
    fs := filesystem.New()

    // 生成证书
    dsa := cryptobin.NewDSA().GenerateKey("L2048N256")
    dsaPriKey := dsa.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword("123", "AES256CBC").
        ToKeyString()
    dsaPubKey := dsa.
        CreatePublicKey().
        ToKeyString()
    fs.Put("./runtime/key/dsa", dsaPriKey)
    fs.Put("./runtime/key/dsa.pub", dsaPubKey)

    // 验证
    dsa := cryptobin.NewDSA()

    dsaPri, _ := fs.Get("./runtime/key/dsa")
    dsacypt := dsa.
        FromString("test-pass").
        FromPrivateKey([]byte(dsaPri)).
        // FromPrivateKeyWithPassword([]byte(dsaPri), "123").
        Sign().
        ToBase64String()
    dsaPub, _ := fs.Get("./runtime/key/dsa.pub")
    dsacyptde := dsa.
        FromBase64String("MjkzNzYzMDE1NjgzNDExMTM0ODE1MzgxOTAxMDIxNzQ0Nzg3NTc3NTAxNTU2MDIwNzg4OTc1MzY4Mzc0OTE5NzcyOTg3NjI1MTc2OTErNDgzNDU3NDAyMzYyODAzMDM3MzE1NjE1NDk1NDEzOTQ4MDQ3NDQ3ODA0MDE4NDY5NDA1OTA3ODExNjM1Mzk3MDEzOTY4MTM5NDg2NDc=").
        FromPublicKey([]byte(dsaPub)).
        Very([]byte("test-pass")).
        ToVeryed()

}
~~~

* 使用 pkcs8 证书
~~~go
// 生成 pkcs8 证书
dsa := cryptobin.NewDSA().GenerateKey("L2048N256")
dsaPriKey := dsa.
    CreatePKCS8PrivateKey().
    // CreatePKCS8PrivateKeyWithPassword("123", "AES256CBC", "SHA256").
    ToKeyString()
dsaPubKey := dsa.
    CreatePKCS8PublicKey().
    ToKeyString()
fs.Put("./runtime/key/dsa_pkcs8", dsaPriKey)
fs.Put("./runtime/key/dsa_pkcs8.pub", dsaPubKey)

// pkcs8 证书验证
dsa := cryptobin.NewDSA()

dsaPri, _ := fs.Get("./runtime/key/dsa_pkcs8")
dsacypt := dsa.
    FromString("test-pass").
    FromPKCS8PrivateKey([]byte(dsaPri)).
    // FromPKCS8PrivateKeyWithPassword([]byte(dsaPri), "123").
    Sign().
    ToBase64String()
dsaPub, _ := fs.Get("./runtime/key/dsa_pkcs8.pub")
dsacyptde := dsa.
    FromBase64String("MjkzNzYzMDE1NjgzNDExMTM0ODE1MzgxOTAxMDIxNzQ0Nzg3NTc3NTAxNTU2MDIwNzg4OTc1MzY4Mzc0OTE5NzcyOTg3NjI1MTc2OTErNDgzNDU3NDAyMzYyODAzMDM3MzE1NjE1NDk1NDEzOTQ4MDQ3NDQ3ODA0MDE4NDY5NDA1OTA3ODExNjM1Mzk3MDEzOTY4MTM5NDg2NDc=").
    FromPKCS8PublicKey([]byte(dsaPub)).
    Very([]byte("test-pass")).
    ToVeryed()
~~~
