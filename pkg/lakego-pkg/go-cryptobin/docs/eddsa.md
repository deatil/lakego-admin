### EdDSA 使用说明

* 使用
~~~go
package main

import (
    "fmt"

    cryptobin "github.com/deatil/go-cryptobin/cryptobin/eddsa"
    "github.com/deatil/lakego-filesystem/filesystem"
)

func main() {
    // 文件管理器
    fs := filesystem.New()

    // 生成证书
    obj := cryptobin.
        NewEdDSA().
        GenerateKey()

    objPriKey := obj.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword("123", "AES256CBC").
        ToKeyString()
    objPubKey := obj.
        CreatePublicKey().
        ToKeyString()
    fs.Put("./runtime/key/eddsa", objPriKey)
    fs.Put("./runtime/key/eddsa.pub", objPubKey)

    // 验证
    obj2 := cryptobin.NewEdDSA()

    obj2Pri, _ := fs.Get("./runtime/key/eddsa")
    obj2cypt := obj2.
        FromString("test-pass").
        FromPrivateKey([]byte(obj2Pri)).
        // FromPrivateKeyWithPassword([]byte(obj2Pri), "123").
        Sign().
        ToBase64String()
    obj2Pub, _ := fs.Get("./runtime/key/eddsa.pub")
    obj2cyptde := obj2.
        FromBase64String("MjkzNzYzMDE1NjgzNDExMTM0ODE1MzgxOTAxMDIxNzQ0Nzg3NTc3NTAxNTU2MDIwNzg4OTc1MzY4Mzc0OTE5NzcyOTg3NjI1MTc2OTErNDgzNDU3NDAyMzYyODAzMDM3MzE1NjE1NDk1NDEzOTQ4MDQ3NDQ3ODA0MDE4NDY5NDA1OTA3ODExNjM1Mzk3MDEzOTY4MTM5NDg2NDc=").
        FromPublicKey([]byte(obj2Pub)).
        Verify([]byte("test-pass")).
        ToVerify()

    // 检测私钥公钥是否匹配
    pri, _ := fs.Get(prifile)
    pub, _ := fs.Get(pubfile)

    res := cryptobin_eddsa.New().
        FromPrivateKey([]byte(pri)).
        FromPublicKey([]byte(pub)).
        CheckKeyPair()

    fmt.Printf("check res: %#v", res)

}
~~~
