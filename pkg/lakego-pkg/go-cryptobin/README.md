## 加密解密


### 项目介绍

*  go-cryptobin 是 go 的常用加密解密库
*  对称加密解密（Aes/Des/TriDes/SM4/Tea/Twofish）
*  对称加密解密模式（ECB/CBC/CFB/OFB/CTR/GCM）
*  对称加密解密补码（NoPadding/ZeroPadding/PKCS5Padding/PKCS7Padding/X923Padding/ISO10126Padding/ISO7816_4Padding/TBCPadding/PKCS1Padding）
*  非对称加密解密（RSA/SM2）
*  非对称签名验证（RSA/PSS/Ecdsa/EdDSA/SM2）
*  默认 `Aes`, `ECB`, `NoPadding`


### 下载安装

~~~go
go get -u github.com/deatil/go-cryptobin
~~~


### 使用

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

    // Des-CBC 加密测试
    cypt2 := cryptobin.
        FromString("test-pass").
        SetKey("dfertf12").
        SetIv("dfertf12").
        Des().
        CBC().
        PKCS7Padding().
        Encrypt().
        ToBase64String()
    cyptde2 := cryptobin.
        FromBase64String("W9LgNgPy/GBU635SnbdSgA==").
        SetKey("dfertf12").
        SetIv("dfertf12").
        Des().
        CBC().
        PKCS7Padding().
        Decrypt().
        ToString()

    // =====

    // TriDes-CFB 加密测试
    var cypt2Err error
    var cypt2Err2 error
    cypt2 := cryptobin.
        FromString("test-pass").
        SetKey("dfertf12dfertf12dfertf12").
        SetIv("dfertf12").
        TriDes().
        CFB().
        PKCS7Padding().
        Encrypt().
        OnError(func(err error) {
            cypt2Err = err
        }).
        ToBase64String()
    cyptde2 := cryptobin.
        FromBase64String("oCqlh4iTOp5+i5SVLN/KUw==").
        SetKey("dfertf12dfertf12dfertf12").
        SetIv("dfertf12").
        TriDes().
        CFB().
        PKCS7Padding().
        Decrypt().
        OnError(func(err error) {
            cypt2Err2 = err
        }).
        ToString()


}

~~~


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
