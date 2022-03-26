## 加密解密


### 项目介绍

*  对称加密（Aes/Des/TriDes）解密
*  非对称（RSA）加密解密
*  默认 `Aes`, `ECB`, `PKCS7Padding`


### 使用方法

~~~go
package main

import (
    "fmt"
    "github.com/deatil/lakego-doak/lakego/support/cryptobin"
)

func main() {
    // 加密
    cypt := cryptobin.
        FromString("useData").
        SetKey("dfertf12dfertf12").
        Aes().
        ECB().
        Pkcs7().
        Encrypt().
        ToBase64String()
    cyptde := cryptobin.
        FromBase64String("i3FhtTp5v6aPJx0wTbarwg==").
        SetKey("dfertf12dfertf12").
        Aes().
        ECB().
        Pkcs7().
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
        EnRsa().
        ToBase64String()
    dekey, _ := fs.Get("./config/key/encrypted-private.key")
    cyptde := cryptobin.
        FromBase64String("AONrSI9z5rn8xWEbR9YfJSA6TRk5mlkuNrCPYqb/koEl63oS6Owhzaev2p1uHIwVV6L+k/dfOZNngIzRbCmf/UU4Fpp/gCxXzh2ZtB1x1Z7orQgUnJdiW9vKJKDGVyBR2znTzTNFD5UpJEOigr2T5VAEhVa4v8ZdxryI4Nlk8cvTSMVbDmz5tMK+2yPJsihsU1TOC8w8PxPPOPfDXDf72D2KrE7ayuCGI8iNVgPQuBkvL7N3t3RLoJzD2uiqcI7afuj59xK6RX/Q6eyrCYRcc1rJkNFSUmGuzzfwlSYYk4zgA+VCwDdhjbPy0Q5LTt3p5bR1FhaufP5SttsmCwTEMw==").
        SetKey(dekey).
        DeRsa("testing").
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

}

~~~
