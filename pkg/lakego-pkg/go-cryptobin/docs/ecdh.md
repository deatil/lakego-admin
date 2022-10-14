### ECDH 使用文档

该版本使用 go 标准库，需要 go 发布带 ecdh 后才能使用，当前为开发版


* ecdh 使用
~~~go
package main

import (
    "fmt"

    "github.com/deatil/lakego-filesystem/filesystem"
    cryptobin_ecdh "github.com/deatil/go-cryptobin/cryptobin/ecdh"
)

func main() {
    // 文件管理器
    fs := filesystem.New()

    // 生成证书
    // 可用参数 [P521 | P384 | P256 | X25519]
    obj := cryptobin_ecdh.New().
        SetCurve("P256").
        GenerateKey()

    objPriKey := obj.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword("123", "AES256CBC").
        ToKeyString()
    objPubKey := obj.
        CreatePublicKey().
        ToKeyString()
    fs.Put("./runtime/key/ecdh/ecdh", objPriKey)
    fs.Put("./runtime/key/ecdh/ecdh.pub", objPubKey)

    // 生成对称加密密钥
    obj := cryptobin_ecdh.New()

    objPri1, _ := fs.Get("./runtime/key/ecdh/ecdh")
    objPub1, _ := fs.Get("./runtime/key/ecdh/ecdh.pub")

    objPri2, _ := fs.Get("./runtime/key/ecdh/ecdh2")
    objPub2, _ := fs.Get("./runtime/key/ecdh/ecdh2.pub")

    objSecret1 := obj.
        FromPrivateKey([]byte(objPri1)).
        // FromPrivateKeyWithPassword([]byte(objPri1), "123").
        FromPublicKey([]byte(objPub2)).
        CreateSecretKey().
        ToHexString()

    objSecret2 := obj.
        FromPrivateKey([]byte(objPri2)).
        // FromPrivateKeyWithPassword([]byte(objPri2), "123").
        FromPublicKey([]byte(objPub1)).
        CreateSecretKey().
        ToHexString()

    dhStatus := false
    if objSecret1 == objSecret2) {
        dhStatus = true
    }

    fmt.Println("生成的密钥是否相同结果: ", dhStatus)
}
~~~
