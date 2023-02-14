## 加密解密
go-cryptobin 是 go 的常用加密解密库


### 项目介绍

*  go-cryptobin 包括常用的对称加密和非对称加密及签名验证
*  对称加密解密（Aes/Des/TriDes/SM4/Tea/Twofish/Xts）
*  对称加密解密模式（ECB/CBC/CFB/OFB/CTR/GCM/CCM）
*  对称加密解密补码（NoPadding/ZeroPadding/PKCS5Padding/PKCS7Padding/X923Padding/ISO10126Padding/ISO97971Padding/ISO7816_4Padding/TBCPadding/PKCS1Padding）
*  非对称加密解密（RSA/SM2）
*  非对称签名验证（RSA/PSS/DSA/Ecdsa/EdDSA/SM2）
*  默认 `Aes`, `ECB`, `NoPadding`


### 下载安装

~~~go
go get -u github.com/deatil/go-cryptobin
~~~


### 开始使用

~~~go
package main

import (
    "fmt"

    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func main() {
    // 加密
    cypt := crypto.
        FromString("useData").
        SetKey("dfertf12dfertf12").
        Aes().
        ECB().
        PKCS7Padding().
        Encrypt().
        ToBase64String()

    // 解密
    cyptde := crypto.
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
}

~~~


### 结构说明

*  默认方式 `Aes`, `ECB`, `NoPadding`
~~~go
// 加密数据
cypt := crypto.
    FromString("useData").
    SetKey("dfertf12dfertf12").
    Encrypt().
    ToBase64String()
// 解密数据
cyptde := crypto.
    FromBase64String("i3FhtTp5v6aPJx0wTbarwg==").
    SetKey("dfertf12dfertf12").
    Decrypt().
    ToString()
~~~

*  结构说明
~~~go
// 使用代码
// 注意: 数据来源,设置密码,加密类型,加密模式,补码方式 在 操作类型 之前, 可以调换顺序
ret := crypto.
    FromString("string"). // 数据来源, 待加密数据/待解密数据
    SetKey("key").        // 设置密码
    SetIv("iv_string").   // 设置向量
    Aes().                // 加密类型
    CBC().                // 加密模式
    PKCS7Padding().       // 补码方式
    Encrypt().            // 操作类型, 加密或者解密
    ToBase64String()      // 返回结果数据类型
~~~


### 可用方法

*  数据来源:
`FromBytes(data []byte)`, `FromString(data string)`, `FromBase64String(data string)`, `FromHexString(data string)`
*  设置密码:
`SetKey(data string)`, `WithKey(key []byte)`
*  设置向量:
`SetIv(data string)`, `WithIv(iv []byte)`
*  加密类型:
`Aes()`, `Des()`, `TriDes()`, `Twofish()`, `Blowfish()`, `Tea(rounds ...int)`, `Xtea()`, `Cast5()`, `SM4()`, `Chacha20(nonce string, counter ...uint32)`, `Chacha20poly1305(nonce string, additional string)`, `RC4()`, `Xts(cipher string, sectorNum uint64)`
*  加密模式:
`ECB()`, `CBC()`, `CFB()`, `OFB()`, `CTR()`, `GCM(nonce string, additional ...string)`, `CCM(nonce string, additional ...string)`
*  补码方式:
`NoPadding()`, `ZeroPadding()`, `PKCS5Padding()`, `PKCS7Padding()`, `X923Padding()`, `ISO10126Padding()`, `ISO7816_4Padding()`, `TBCPadding()`, `PKCS1Padding(bt ...string)`
*  操作类型:
`Encrypt()`, `Decrypt()`, `FuncEncrypt(f func(Cryptobin) Cryptobin)`, `FuncDecrypt(f func(Cryptobin) Cryptobin)`
`RsaEncrypt()`, `RsaDecrypt(password ...string)`,
`RsaPrikeyEncrypt(password ...string)`, `RsaPubkeyDecrypt()`,
`RsaOAEPEncrypt(typ string)`, `RsaOAEPDecrypt(typ string, password ...string)`,
`SM2Encrypt()`, `SM2Decrypt(password ...string)`,
*  返回数据类型:
`ToBytes()`, `ToString()`, `ToBase64String()`, `ToHexString()`

*  更多信息可以查看 [文档](docs/README.md)


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
