### EcDsa 使用说明

* 常规使用
~~~go
package main

import (
    "fmt"

    "github.com/deatil/go-cryptobin/cryptobin/ecdsa"
    "github.com/deatil/lakego-filesystem/filesystem"
)

func main() {
    // 文件管理器
    fs := filesystem.New()

    // 生成证书
    // 可选参数 [P521 | P384 | P256 | P224]
    obj := ecdsa.
        New().
        SetCurve("P521").
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
    obj2 := ecdsa.New()

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

    // 签名验证对
    Sign(separator ...string) / Verify(data []byte, separator ...string)
    SignASN1() / VerifyASN1(data []byte)
    SignAsn1() / VerifyAsn1(data []byte)
    SignHex() / VerifyHex(data []byte)

    // 检测私钥公钥是否匹配
    pri, _ := fs.Get(prifile)
    pub, _ := fs.Get(pubfile)

    res := ecdsa.New().
        FromPrivateKey([]byte(pri)).
        FromPublicKey([]byte(pub)).
        CheckKeyPair()

    fmt.Printf("check res: %#v", res)

    // =====

    enprikey = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGfqpFWW2kecvy/V0mxus+ZMuODGcqfyZVJMgBbWRhYJoAoGCCqGSM49
AwEHoUQDQgAEqktVUz5Og3mBcnhpnfWWSOhrZqO+Vu0zCh5hkl/0r9vPzPeqGpHJ
v3eJw/zF+gZWxn2LvLcKkQTcGutSwVdVRQ==
-----END EC PRIVATE KEY-----
    `

    enpubkey = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqktVUz5Og3mBcnhpnfWWSOhrZqO+
Vu0zCh5hkl/0r9vPzPeqGpHJv3eJw/zF+gZWxn2LvLcKkQTcGutSwVdVRQ==
-----END PUBLIC KEY-----
    `

    // 加密解密
    obj := ecdsa.New()

    // 加密
    objcypt := obj.
        FromString("test-pass").
        FromPublicKey([]byte(enpubkey)).
        Encrypt().
        ToBase64String()

    // 解密
    endata := "BA6UmWJHLf/XOhge8ASuz11cMpX3YCu6Pfmp5tQ/OPK7rV27paYGB6V5vL/KhjVGznedvhGe0F3CNzoyxfp+r+41m+ehtIC0isWnDc8ZyZrmNVioOeaO5i6yEwiEwhTB8QzUSDE5JJB6ta0vObhBvFRVvgzv1VD0C4Y="
    objcyptde := obj.
        FromBase64String(endata).
        FromPrivateKey([]byte(enprikey)).
        Decrypt().
        ToString()

}
~~~
