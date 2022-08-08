### DH 使用文档

* DH 使用
~~~go
package main

import (
    "fmt"

    "github.com/deatil/lakego-filesystem/filesystem"
    cryptobin_dh "github.com/deatil/go-cryptobin/cryptobin/dh/dh"
)

func main() {
    // 文件管理器
    fs := filesystem.New()

    // 生成证书
    // 可用参数 [P512 | P1024 | P2048_2 | P2048 | P3072 | P4096]
    obj := cryptobin_dh.New().
        GenerateKey("P512")

    objPriKey := obj.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword("123", "AES256CBC").
        ToKeyString()
    objPubKey := obj.
        CreatePublicKey().
        ToKeyString()
    fs.Put("./runtime/key/dhd2/dh1", objPriKey)
    fs.Put("./runtime/key/dhd2/dh1.pub", objPubKey)

    // 验证
    obj := cryptobin_dh.New()

    objPri1, _ := fs.Get("./runtime/key/dhd/dh")
    objPub1, _ := fs.Get("./runtime/key/dhd/dh.pub")

    objPri2, _ := fs.Get("./runtime/key/dhd/dh2")
    objPub2, _ := fs.Get("./runtime/key/dhd/dh2.pub")

    objSecret1 := obj.
        FromPrivateKey([]byte(objPri1)).
        // FromPrivateKeyWithPassword([]byte(objPri1), "123").
        FromPublicKey([]byte(objPub2)).
        CreateSecret().
        ToHexString()

    objSecret2 := obj.
        FromPrivateKey([]byte(objPri2)).
        // FromPrivateKeyWithPassword([]byte(objPri2), "123").
        FromPublicKey([]byte(objPub1)).
        CreateSecret().
        ToHexString()

    dhStatus := false
    if objSecret1 == objSecret2) {
        dhStatus = true
    }

    fmt.Println("生成的密钥是否相同结果: ", dhStatus)
}
~~~

* ecdh 使用
~~~go
package main

import (
    "fmt"

    "github.com/deatil/lakego-filesystem/filesystem"
    cryptobin_ecdh "github.com/deatil/go-cryptobin/cryptobin/dh/ecdh"
)

func main() {
    // 文件管理器
    fs := filesystem.New()

    // 生成证书
    // 可用参数 [P521 | P384 | P256 | P224]
    obj := cryptobin_ecdh.New().
        GenerateKey("P521")

    objPriKey := obj.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword("123", "AES256CBC").
        ToKeyString()
    objPubKey := obj.
        CreatePublicKey().
        ToKeyString()
    fs.Put("./runtime/key/dhd2/dh2", objPriKey)
    fs.Put("./runtime/key/dhd2/dh2.pub", objPubKey)

    // 验证
    obj := cryptobin_ecdh.New()

    objPri1, _ := fs.Get("./runtime/key/dhd/ecdh")
    objPub1, _ := fs.Get("./runtime/key/dhd/ecdh.pub")

    objPri2, _ := fs.Get("./runtime/key/dhd/ecdh2")
    objPub2, _ := fs.Get("./runtime/key/dhd/ecdh2.pub")

    objSecret1 := obj.
        FromPrivateKey([]byte(objPri1)).
        // FromPrivateKeyWithPassword([]byte(objPri1), "123").
        FromPublicKey([]byte(objPub2)).
        CreateSecret().
        ToHexString()

    objSecret2 := obj.
        FromPrivateKey([]byte(objPri2)).
        // FromPrivateKeyWithPassword([]byte(objPri2), "123").
        FromPublicKey([]byte(objPub1)).
        CreateSecret().
        ToHexString()

    dhStatus := false
    if objSecret1 == objSecret2) {
        dhStatus = true
    }

    fmt.Println("生成的密钥是否相同结果: ", dhStatus)
}
~~~

* curve25519 使用
~~~go
package main

import (
    "fmt"

    "github.com/deatil/lakego-filesystem/filesystem"
    cryptobin_curve "github.com/deatil/go-cryptobin/cryptobin/dh/curve25519"
)

func main() {
    // 文件管理器
    fs := filesystem.New()

    // 生成证书
    obj := cryptobin_curve.New().
        GenerateKey()

    objPriKey := obj.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword("123", "AES256CBC").
        ToKeyString()
    objPubKey := obj.
        CreatePublicKey().
        ToKeyString()
    fs.Put("./runtime/key/dhd2/dh3", objPriKey)
    fs.Put("./runtime/key/dhd2/dh3.pub", objPubKey)

    // curve25519 验证
    obj := cryptobin_curve.New()

    objPri1, _ := fs.Get("./runtime/key/dhd/cu")
    objPub1, _ := fs.Get("./runtime/key/dhd/cu.pub")

    objPri2, _ := fs.Get("./runtime/key/dhd/cu2")
    objPub2, _ := fs.Get("./runtime/key/dhd/cu2.pub")

    objSecret1 := obj.
        FromPrivateKey([]byte(objPri1)).
        // FromPrivateKeyWithPassword([]byte(objPri1), "123").
        FromPublicKey([]byte(objPub2)).
        CreateSecret().
        ToHexString()

    objSecret2 := obj.
        FromPrivateKey([]byte(objPri2)).
        // FromPrivateKeyWithPassword([]byte(objPri2), "123").
        FromPublicKey([]byte(objPub1)).
        CreateSecret().
        ToHexString()

    dhStatus := false
    if objSecret1 == objSecret2) {
        dhStatus = true
    }

    fmt.Println("生成的密钥是否相同结果: ", dhStatus)
}
~~~
