### EcDsa 使用说明

* 常规使用
~~~go
package main

import (
    "fmt"

    cryptobin "github.com/deatil/go-cryptobin/cryptobin/ecdsa"
    "github.com/deatil/lakego-filesystem/filesystem"
)

func main() {
    // 文件管理器
    fs := filesystem.New()

    // 生成证书
    // 可选参数 [P521 | P384 | P256 | P224]
    obj := cryptobin.
        NewEcdsa().
        WithCurve("P521").
        GenerateKey()

    objPriKey := obj.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword("123", "AES256CBC").
        // CreatePKCS8PrivateKey().
        // CreatePKCS8PrivateKeyWithPassword("123", "AES256CBC", "SHA256").
        ToKeyString()
    objPubKey := obj.
        CreatePublicKey().
        ToKeyString()
    fs.Put("./runtime/key/ecdsa", objPriKey)
    fs.Put("./runtime/key/ecdsa.pub", objPubKey)

    // 验证
    obj2 := cryptobin.NewEcdsa()

    obj2Pri, _ := fs.Get("./runtime/key/ecdsa")
    obj2cypt := obj2.
        FromString("test-pass").
        FromPrivateKey([]byte(obj2Pri)).
        // FromPrivateKeyWithPassword([]byte(obj2Pri), "123").
        // FromPKCS8PrivateKey([]byte(obj2Pri)).
        // FromPKCS8PrivateKeyWithPassword([]byte(obj2Pri), "123").
        Sign().
        ToBase64String()
    obj2Pub, _ := fs.Get("./runtime/key/ecdsa.pub")
    obj2cyptde := obj2.
        FromBase64String("MjkzNzYzMDE1NjgzNDExMTM0ODE1MzgxOTAxMDIxNzQ0Nzg3NTc3NTAxNTU2MDIwNzg4OTc1MzY4Mzc0OTE5NzcyOTg3NjI1MTc2OTErNDgzNDU3NDAyMzYyODAzMDM3MzE1NjE1NDk1NDEzOTQ4MDQ3NDQ3ODA0MDE4NDY5NDA1OTA3ODExNjM1Mzk3MDEzOTY4MTM5NDg2NDc=").
        FromPublicKey([]byte(obj2Pub)).
        Verify([]byte("test-pass")).
        ToVerify()

    // 检测私钥公钥是否匹配
    pri, _ := fs.Get(prifile)
    pub, _ := fs.Get(pubfile)

    res := cryptobin_ecdsa.New().
        FromPrivateKey([]byte(pri)).
        FromPublicKey([]byte(pub)).
        CheckKeyPair()

    fmt.Printf("check res: %#v", res)

}
~~~
