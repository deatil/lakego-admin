### ElGamal 使用说明

* 使用 [pkcs1 / pkcs8] 证书，默认为 pkcs1 证书
~~~go
package main

import (
    "fmt"

    "github.com/deatil/lakego-filesystem/filesystem"
    "github.com/deatil/go-cryptobin/cryptobin/elgamal"
)

func main() {
    // 文件管理器
    fs := filesystem.New()

    // 生成证书
    elg := elgamal.New().GenerateKey(256, 64)
    elgPriKey := elg.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword("123", "DESEDE3CBC").
        // CreatePKCS1PrivateKey().
        // CreatePKCS1PrivateKeyWithPassword("123", "DESEDE3CBC").
        // CreatePKCS8PrivateKey().
        // CreatePKCS8PrivateKeyWithPassword("123", "AES256CBC").
        ToKeyString()
    elgPubKey := elg.
        CreatePublicKey().
        // CreatePKCS1PublicKey().
        // CreatePKCS8PublicKey().
        ToKeyString()
    fs.Put("./runtime/key/elg", elgPriKey)
    fs.Put("./runtime/key/elg.pub", elgPubKey)

    // 验证
    elg := elgamal.New()

    elgPri, _ := fs.Get("./runtime/key/elg")
    elgcypt := elg.
        FromString("test-pass").
        FromPrivateKey([]byte(elgPri)).
        // FromPrivateKeyWithPassword([]byte(elgPri), "123").
        // FromPKCS1PrivateKey([]byte(elgPri)).
        // FromPKCS1PrivateKeyWithPassword([]byte(elgPri), "123").
        // FromPKCS8PrivateKey([]byte(elgPri)).
        // FromPKCS8PrivateKeyWithPassword([]byte(elgPri), "123").
        Sign().
        ToBase64String()
    elgPub, _ := fs.Get("./runtime/key/elg.pub")
    elgcyptde := elg.
        FromBase64String("MjkzNzYzMDE1NjgzNDExMTM0ODE1MzgxOTAxMDIxNzQ0Nzg3NTc3NTAxNTU2MDIwNzg4OTc1MzY4Mzc0OTE5NzcyOTg3NjI1MTc2OTErNDgzNDU3NDAyMzYyODAzMDM3MzE1NjE1NDk1NDEzOTQ4MDQ3NDQ3ODA0MDE4NDY5NDA1OTA3ODExNjM1Mzk3MDEzOTY4MTM5NDg2NDc=").
        FromPublicKey([]byte(elgPub)).
        // FromPKCS1PublicKey([]byte(elgPub)).
        // FromPKCS8PublicKey([]byte(elgPub)).
        Verify([]byte("test-pass")).
        ToVerify()

    // 加密解密
    elg := elgamal.New()

    elgPub, _ := fs.Get("./runtime/key/elg.pub")
    elgcypt := elg.
        FromString("test-pass").
        FromPublicKey([]byte(elgPub)).
        // FromPKCS1PublicKey([]byte(elgPub)).
        // FromPKCS8PublicKey([]byte(elgPub)).
        Encrypt().
        ToBase64String()
    elgPri, _ := fs.Get("./runtime/key/elg")
    elgcyptde := elg.
        FromBase64String("MjkzNzYzMDE1NjgzNDExMTM0ODE1MzgxOTAxMDIxNzQ0Nzg3NTc3NTAxNTU2MDIwNzg4OTc1MzY4Mzc0OTE5NzcyOTg3NjI1MTc2OTErNDgzNDU3NDAyMzYyODAzMDM3MzE1NjE1NDk1NDEzOTQ4MDQ3NDQ3ODA0MDE4NDY5NDA1OTA3ODExNjM1Mzk3MDEzOTY4MTM5NDg2NDc=").
        FromPrivateKey([]byte(elgPri)).
        // FromPrivateKeyWithPassword([]byte(elgPri), "123").
        // FromPKCS1PrivateKey([]byte(elgPri)).
        // FromPKCS1PrivateKeyWithPassword([]byte(elgPri), "123").
        // FromPKCS8PrivateKey([]byte(elgPri)).
        // FromPKCS8PrivateKeyWithPassword([]byte(elgPri), "123").
        Decrypt().
        ToVerify()

    // 检测私钥公钥是否匹配
    pri, _ := fs.Get(prifile)
    pub, _ := fs.Get(pubfile)

    res := elgamal.New().
        FromPrivateKey([]byte(pri)).
        // FromPrivateKeyWithPassword([]byte(pri), "123").
        FromPublicKey([]byte(pub)).
        // FromPKCS1PrivateKey([]byte(pri)).
        // FromPKCS1PrivateKeyWithPassword([]byte(pri), "123").
        // FromPKCS1PublicKey([]byte(pub)).
        // FromPKCS8PrivateKey([]byte(pri)).
        // FromPKCS8PrivateKeyWithPassword([]byte(pri), "123").
        // FromPKCS8PublicKey([]byte(pub)).
        CheckKeyPair()

    fmt.Printf("check res: %#v", res)

}
~~~
