## 加密解密


### 项目介绍

*  对称加密解密（Aes/Des/TriDes）
*  非对称加密解密（RSA）
*  默认 `Aes`, `ECB`, `PKCS7Padding`


### 使用方法

~~~go
package main

import (
    "fmt"

    "github.com/deatil/go-cryptobin/cryptobin"
)

func main() {
    // 加密
    cypt := cryptobin.
        FromString("useData").
        SetKey("dfertf12dfertf12").
        Aes().
        ECB().
        PKCS7Padding().
        Encrypt().
        ToBase64String()
    cyptde := cryptobin.
        FromBase64String("i3FhtTp5v6aPJx0wTbarwg==").
        SetKey("dfertf12dfertf12").
        Aes().
        ECB().
        PKCS7Padding().
        Decrypt().
        ToString()

    // i3FhtTp5v6aPJx0wTbarwg==
    fmt.Println("加密结果：", cypt)
    fmt.Println("解密结果：", cyptde)

    // =====

    // Des 加密测试
    cypt := cryptobin.
        FromString("test-pass").
        SetIv("ftr4tywe").
        SetKey("dfertf12").
        Des().
        ECB().
        PKCS7Padding().
        Encrypt().
        ToBase64String()
    cyptde := cryptobin.
        FromBase64String("bvifBivJ1GEJ0N/UiZry/A==").
        SetIv("ftr4tywe").
        SetKey("dfertf12").
        Des().
        ECB().
        PKCS7Padding().
        Decrypt().
        ToString()

    // =====

    // TriDes 加密测试
    cypt := cryptobin.
        FromString("test-pass").
        SetIv("ftr4tyew").
        SetKey("dfertf12dfertf12dfertf12").
        TriDes().
        ECB().
        PKCS7Padding().
        Encrypt().
        ToHexString()
    cyptde := cryptobin.
        FromHexString("6ef89f062bc9d46109d0dfd4899af2fc").
        SetIv("ftr4tyew").
        SetKey("dfertf12dfertf12dfertf12").
        TriDes().
        ECB().
        PKCS7Padding().
        Decrypt().
        ToString()

    // =====

    // RSA 加密测试
    enkey, _ := fs.Get("./config/key/encrypted-public.key")
    cypt := cryptobin.
        FromString("test-pass").
        SetKey(enkey).
        RsaEncrypt().
        ToBase64String()
    dekey, _ := fs.Get("./config/key/encrypted-private.key")
    cyptde := cryptobin.
        FromBase64String("AONrSI9z5rn8xWEbR9YfJSA6TRk5mlkuNrCPYqb/koEl63oS6Owhzaev2p1uHIwVV6L+k/dfOZNngIzRbCmf/UU4Fpp/gCxXzh2ZtB1x1Z7orQgUnJdiW9vKJKDGVyBR2znTzTNFD5UpJEOigr2T5VAEhVa4v8ZdxryI4Nlk8cvTSMVbDmz5tMK+2yPJsihsU1TOC8w8PxPPOPfDXDf72D2KrE7ayuCGI8iNVgPQuBkvL7N3t3RLoJzD2uiqcI7afuj59xK6RX/Q6eyrCYRcc1rJkNFSUmGuzzfwlSYYk4zgA+VCwDdhjbPy0Q5LTt3p5bR1FhaufP5SttsmCwTEMw==").
        SetKey(dekey).
        RsaDecrypt("testing").
        ToString()

    // =====

    // 获取报错数据
    err := cryptobin.
        FromString("test-pass").
        SetIv("ftr4tyew").
        SetKey("dfertf12dfertf12dfertf12ty").
        TriDes().
        ECB().
        PKCS7Padding().
        Encrypt().
        Error.
        Error()

    // 生成证书
    rsa := cryptobin.NewRsa()
    rsaPriKey := rsa.
        GenerateKey(2048).
        CreatePKCS8WithPassword("123", "AES256CBC", "SHA256").
        ToKeyString()
    rsaPubKey := rsa.
        FromPKCS8WithPassword([]byte(rsaPriKey), "123").
        CreatePublicKey().
        ToKeyString()

    // =====

    // Ecdsa
    ecdsa := cryptobin.NewEcdsa()
    rsaPriKey := ecdsa.
        WithCurve("P521").
        GenerateKey().
        CreatePrivateKey().
        ToKeyString()
    rsaPubKey := ecdsa.
        FromPrivateKey([]byte(rsaPriKey)).
        WithCurve("P521").
        CreatePublicKey().
        ToKeyString()

    // =====

    // Ecdsa 验证
    pri, _ := fs.Get("./runtime/key/ec256-private.pem")
    pub, _ := fs.Get("./runtime/key/ec256-public.pem")
    ecdsa := cryptobin.NewEcdsa()
    rsaPriKey := ecdsa.
        FromPrivateKey([]byte(pri)).
        FromString("测试").
        Sign().
        ToBase64String()
    rsaPubKey := ecdsa.
        FromBase64String(rsaPriKey).
        FromPublicKey([]byte(pub)).
        Very([]byte("测试")).
        ToVeryed()

    // =====

    // PSS 验证
    pri, _ := fs.Get("./runtime/key/sample_key")
    pub, _ := fs.Get("./runtime/key/sample_key.pub")
    rsa := cryptobin.NewRsa()
    rsaPriKey := rsa.
        FromPrivateKey([]byte(pri)).
        FromString("测试").
        WithSignHash("SHA256").
        PSSSign().
        ToBase64String()
    rsaPubKey := rsa.
        FromBase64String(rsaPriKey).
        FromPublicKey([]byte(pub)).
        WithSignHash("SHA256").
        PSSVery([]byte("测试")).
        ToVeryed()

    // =====

    // 生成 eddsa 证书
    eddsa := cryptobin.NewEdDSA().GenerateKey()
    eddsaPriKey := eddsa.
        CreatePrivateKey().
        ToKeyString()
    eddsaPubKey := eddsa.
        CreatePublicKey().
        ToKeyString()

    fs.Put("./runtime/key/eddsa_key", eddsaPriKey)
    fs.Put("./runtime/key/eddsa_key.pub", eddsaPubKey)

    // =====

    // eddsa 验证
    pri, _ := fs.Get("./runtime/key/eddsa_key")
    pub, _ := fs.Get("./runtime/key/eddsa_key.pub")
    rsa := cryptobin.NewEdDSA()
    rsaPriKey := rsa.
        FromPrivateKey([]byte(pri)).
        FromString("测试").
        Sign().
        ToBase64String()
    rsaPubKey := rsa.
        FromBase64String(rsaPriKey).
        FromPublicKey([]byte(pub)).
        Very([]byte("测试")).
        ToVeryed()

    // =====

    // Chacha20poly1305 加密测试
    cypt := cryptobin.
        FromString("test-pass").
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        Chacha20poly1305([]byte("werfrewerfre"), []byte("ftyhg5")).
        Encrypt().
        ToBase64String()
    cyptde := cryptobin.
        FromBase64String("c2c0u6OYvU0EmsFapoCfiLky+OakQW9x/A==").
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        Chacha20poly1305([]byte("werfrewerfre"), []byte("ftyhg5")).
        Decrypt().
        ToString()

    // =====

    // RC4 加密测试
    cypt := cryptobin.
        FromString("test-pass").
        SetKey("dfertf12dfertf12dfertf12").
        RC4().
        Encrypt().
        ToHexString()
    cyptde := cryptobin.
        FromHexString("4308d5f24be9195317").
        SetKey("dfertf12dfertf12dfertf12").
        RC4().
        Decrypt().
        ToString()

    // =====

    // Chacha20 加密测试
    cypt := cryptobin.
        FromString("test-pass").
        SetKey("dfertf12dfertf12dfertf12ghy6yhtg").
        Chacha20([]byte("fgr5tfgr5rtr")).
        Encrypt().
        ToHexString()
    cyptde := cryptobin.
        FromHexString("a87757b7196994e818").
        SetKey("dfertf12dfertf12dfertf12ghy6yhtg").
        Chacha20([]byte("fgr5tfgr5rtr")).
        Decrypt().
        ToString()

}

~~~


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
