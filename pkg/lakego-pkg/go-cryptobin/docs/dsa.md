### DSA 使用说明

* 使用 [pkcs1 / pkcs8] 证书，默认为 pkcs1 证书
~~~go
package main

import (
    "fmt"

    "github.com/deatil/lakego-filesystem/filesystem"
    cryptobin_dsa "github.com/deatil/go-cryptobin/cryptobin/dsa"
)

func main() {
    // 文件管理器
    fs := filesystem.New()

    // 生成证书
    // 可用参数 [L1024N160 | L2048N224 | L2048N256 | L3072N256]
    dsa := cryptobin_dsa.New().GenerateKey("L2048N256")
    dsaPriKey := dsa.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword("123", "AES256CBC").
        // CreatePKCS8PrivateKey().
        // CreatePKCS8PrivateKeyWithPassword("123", "AES256CBC").
        ToKeyString()
    dsaPubKey := dsa.
        CreatePublicKey().
        // CreatePKCS8PublicKey().
        ToKeyString()
    fs.Put("./runtime/key/dsa", dsaPriKey)
    fs.Put("./runtime/key/dsa.pub", dsaPubKey)

    // 验证
    dsa := cryptobin_dsa.New()

    dsaPri, _ := fs.Get("./runtime/key/dsa")
    dsacypt := dsa.
        FromString("test-pass").
        FromPrivateKey([]byte(dsaPri)).
        // FromPrivateKeyWithPassword([]byte(dsaPri), "123").
        // FromPKCS8PrivateKey([]byte(dsaPri)).
        // FromPKCS8PrivateKeyWithPassword([]byte(dsaPri), "123").
        Sign().
        ToBase64String()
    dsaPub, _ := fs.Get("./runtime/key/dsa.pub")
    dsacyptde := dsa.
        FromBase64String("MjkzNzYzMDE1NjgzNDExMTM0ODE1MzgxOTAxMDIxNzQ0Nzg3NTc3NTAxNTU2MDIwNzg4OTc1MzY4Mzc0OTE5NzcyOTg3NjI1MTc2OTErNDgzNDU3NDAyMzYyODAzMDM3MzE1NjE1NDk1NDEzOTQ4MDQ3NDQ3ODA0MDE4NDY5NDA1OTA3ODExNjM1Mzk3MDEzOTY4MTM5NDg2NDc=").
        FromPublicKey([]byte(dsaPub)).
        // FromPKCS8PublicKey([]byte(dsaPub)).
        Verify([]byte("test-pass")).
        ToVerify()

    // 检测私钥公钥是否匹配
    pri, _ := fs.Get(prifile)
    pub, _ := fs.Get(pubfile)

    res := cryptobin_dsa.New().
        FromPKCS8PrivateKey([]byte(pri)).
        // FromPrivateKey([]byte(pri)).
        // FromPrivateKeyWithPassword([]byte(pri), "123").
        // FromPKCS8PrivateKeyWithPassword([]byte(pri), "123").
        // FromPublicKey([]byte(pub)).
        FromPKCS8PublicKey([]byte(pub)).
        CheckKeyPair()

    fmt.Printf("check res: %#v", res)

}
~~~
