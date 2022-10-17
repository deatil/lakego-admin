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
    // 可用参数 [P1001 | P1002 | P1536 | P2048 | P3072 | P4096 | P6144 | P8192]
    obj := cryptobin_dh.New().
        SetGroup("P512").
        GenerateKey()

    objPriKey := obj.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword("123", "AES256CBC").
        ToKeyString()
    objPubKey := obj.
        CreatePublicKey().
        ToKeyString()
    fs.Put("./runtime/key/dh2/dh1", objPriKey)
    fs.Put("./runtime/key/dh2/dh1.pub", objPubKey)

    // 验证
    obj := cryptobin_dh.New()

    objPri1, _ := fs.Get("./runtime/key/dh/dh")
    objPub1, _ := fs.Get("./runtime/key/dh/dh.pub")

    objPri2, _ := fs.Get("./runtime/key/dh/dh2")
    objPub2, _ := fs.Get("./runtime/key/dh/dh2.pub")

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
        SetCurve("P521").
        GenerateKey()

    objPriKey := obj.
        CreatePrivateKey().
        // CreatePrivateKeyWithPassword("123", "AES256CBC").
        ToKeyString()
    objPubKey := obj.
        CreatePublicKey().
        ToKeyString()
    fs.Put("./runtime/key/dh2/dh2", objPriKey)
    fs.Put("./runtime/key/dh2/dh2.pub", objPubKey)

    // 验证
    obj := cryptobin_ecdh.New()

    objPri1, _ := fs.Get("./runtime/key/dh/ecdh")
    objPub1, _ := fs.Get("./runtime/key/dh/ecdh.pub")

    objPri2, _ := fs.Get("./runtime/key/dh/ecdh2")
    objPub2, _ := fs.Get("./runtime/key/dh/ecdh2.pub")

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
    fs.Put("./runtime/key/dh2/dh3", objPriKey)
    fs.Put("./runtime/key/dh2/dh3.pub", objPubKey)

    // curve25519 验证
    obj := cryptobin_curve.New()

    objPri1, _ := fs.Get("./runtime/key/dh/cu")
    objPub1, _ := fs.Get("./runtime/key/dh/cu.pub")

    objPri2, _ := fs.Get("./runtime/key/dh/cu2")
    objPub2, _ := fs.Get("./runtime/key/dh/cu2.pub")

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

* 自定义使用使用
~~~go
package main

import (
    "fmt"
    "math/big"

    "github.com/deatil/lakego-filesystem/filesystem"
    dh_dh "github.com/deatil/go-cryptobin/dh/dh"
    cryptobin_dh "github.com/deatil/go-cryptobin/cryptobin/dh/dh"
)

func main() {
    // 文件管理器
    fs := filesystem.New()

    // 自定义生成证书
    gp, _ := dh_dh.GetMODPGroup(dh_dh.P3072)
    priv := &dh_dh.PrivateKey{}
    priv.X, _ = new(big.Int).SetString("b4d8c5ed186d7ae4538003b390467195f907f1ae30bb14d0a6a17325d43deec9", 16)
    priv.PublicKey.Y, _ = new(big.Int).SetString("b10700012504a616b799ff09f29b8fac42a9e37bd2c64150bfe7b788a041e75e82934565db76cd6fa346b140e3448b01c93dc7eb9193800ffb73dde828566922a0aed9d913af6be383461f0bcb48347dc1183b2815b9dc82136bcfc2de0a25573def474f56e864f769c1aa5e27b70d2843e36f3de69375824556ccc9e9e15abfb4792973b5d95124742d72bc90cc109e802018c087a9942439d2adf3568a58249f59e6f8c6de55b5f2d30cf6235b61a6bc2d2ecbc44b42e0f5d228fae745c5f31699a7a53bb33c48e4ff811e2453df4a547c82bd4283e195a38f9af23a1668b45705865243490a3c5a90e7f82373c9ef01dea457472f0d31a4cfb3b42b75a4864f16adee1323f6479f058cf22e6dc3e575ba650e043a8ac0ab78db5fbfa912aab938f37d110afd800a4897f01785b1c63a83064945b677418a27db2f51828f10ca69d0cc6910a5d6709cecdbfc7b326278e2a7f69151a6dc011e9fe8a286f016898d8c52fe24f041a9db7f60b6378dc644050c4db009a1ae817dab5fafd4338b", 16)
    priv.PublicKey.Parameters = dh_dh.Parameters{
        P: gp.P,
        G: gp.G,
    }

    obj22 := cryptobin_dh.New().
        WithPrivateKey(priv)

    objPriKey := obj22.
        CreatePrivateKeyWithPassword("123", "AES256CBC").
        ToKeyString()
    objPubKey := obj22.
        MakePublicKey().
        CreatePublicKey().
        ToKeyString()

    fs.Put("./runtime/key/dh2/dh1_dhkey", objPriKey)
    fs.Put("./runtime/key/dh2/dh1_dhkey.pub", objPubKey)
}
~~~

* 自定义使用使用2
~~~go
package main

import (
    "fmt"
    "math/big"

    "github.com/deatil/lakego-filesystem/filesystem"
    cryptobin_dh "github.com/deatil/go-cryptobin/cryptobin/dh/dh"
)

func main() {
    // 文件管理器
    fs := filesystem.New()

    obj222P, _ := new(big.Int).SetString("952d7308282592a9a3230623985e1029a9ce3a51845f90047ad4fca9c587042fbe04219ed80e86a5610b180b8da38d5f4ed6ab10bc356b99021d3497cf280e0e40dc4520293870db44425903febcb9e5e12d55921e69057552cf8859a3d4dc3b3f588f733bffe991962ece8df0458bc79d07054582349a214ed52889b60821a3", 16)
    obj222 := cryptobin_dh.New().
        WithGroup(&cryptobin_dh.Group{
            P: obj222P,
            G: big.NewInt(2),
        }).
        GenerateKey()

    objPriKey := obj222.
        CreatePrivateKey().
        ToKeyString()
    objPubKey := obj222.
        CreatePublicKey().
        ToKeyString()
    fs.Put("./runtime/key/dh5/dh_web2", objPriKey)
    fs.Put("./runtime/key/dh5/dh_web2.pub", objPubKey)
}
~~~
