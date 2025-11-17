## go-cryptobin

go-cryptobin 是一个简单易用并且兼容性高的 go 语言加密解密库

<p align="left">
<a href="https://pkg.go.dev/github.com/deatil/go-cryptobin" ><img src="https://pkg.go.dev/badge/deatil/go-cryptobin.svg" alt="Go Reference"></a>
<a href="https://codecov.io/gh/deatil/go-cryptobin" ><img src="https://codecov.io/gh/deatil/go-cryptobin/graph/badge.svg?token=SS2Z1IY0XL"/></a>
<a href="https://goreportcard.com/report/github.com/deatil/go-cryptobin" ><img src="https://goreportcard.com/badge/github.com/deatil/go-cryptobin" /></a>
</p>

[English](README.md) | 中文


### 项目介绍

*  go-cryptobin 包括常用的对称加密和非对称加密及签名验证
*  对称加密解密（Aes/Des/TripleDes/SM4/Tea/Twofish/Xts）
*  对称加密解密模式（ECB/CBC/PCBC/CFB/NCFB/OFB/NOFB/CTR/GCM/CCM）
*  对称加密解密补码（NoPadding/ZeroPadding/PKCS5Padding/PKCS7Padding/X923Padding/ISO10126Padding/ISO97971Padding/ISO7816_4Padding/PBOC2Padding/TBCPadding/PKCS1Padding）
*  非对称加密解密（RSA/SM2/ElGamal）
*  非对称签名验证（RSA/RSA-PSS/DSA/ECDSA/EC-GDSA/EdDSA/SM2/ElGamal/ED448/Gost）
*  默认 `Aes`, `ECB`, `NoPadding`


### 环境要求

 - Go >= 1.20


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
    cypten := crypto.
        FromString("useData").
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        CBC().
        PKCS7Padding().
        Encrypt().
        ToBase64String()

    // 解密
    cyptde := crypto.
        FromBase64String(cypten).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        CBC().
        PKCS7Padding().
        Decrypt().
        ToString()

    fmt.Println("加密结果：", cypten)
    fmt.Println("解密结果：", cyptde)
}

~~~


### 结构说明

*  默认方式 `Aes`, `ECB`, `NoPadding`。默认没有用补码, 默认输入值需为 16 长度倍数, 不是正确长度可以使用其他补码
~~~go
// 加密数据
cypt := crypto.
    FromString("useData5useData5").
    SetKey("dfertf12dfertf12").
    Encrypt().
    ToBase64String()

// 解密数据
cyptde := crypto.
    FromBase64String("eZf7c3fcwKlmrqogiEHbJg==").
    SetKey("dfertf12dfertf12").
    Decrypt().
    ToString()
~~~

*  结构说明
~~~go
// 使用代码
// 注意: 设置密码,加密类型,加密模式,补码方式 在 操作类型 之前, 可以调换顺序
ret := crypto.
    FromString("string"). // 数据来源, 待加密数据/待解密数据
    SetKey("key_string"). // 设置密码
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
`Aes()`, `Des()`, `TripleDes()`, `Twofish()`, `Blowfish()`, `Tea(rounds ...int)`, `Xtea()`, `Cast5()`, `RC4()`, `Idea()`, `SM4()`, `Chacha20(counter ...uint32)`, `Chacha20poly1305(additional ...[]byte)`, `Xts(cipher string, sectorNum uint64)`
*  加密模式:
`ECB()`, `CBC()`, `PCBC()`, `CFB()`, `OFB()`, `CTR()`, `GCM(additional ...[]byte)`, `CCM(additional ...[]byte)`
*  补码方式:
`NoPadding()`, `ZeroPadding()`, `PKCS5Padding()`, `PKCS7Padding()`, `X923Padding()`, `ISO10126Padding()`, `ISO7816_4Padding()`,`ISO97971Padding()`,`PBOC2Padding()`, `TBCPadding()`, `PKCS1Padding(bt ...string)`
*  操作类型:
`Encrypt()`, `Decrypt()`, `FuncEncrypt(f func(Cryptobin) Cryptobin)`, `FuncDecrypt(f func(Cryptobin) Cryptobin)`
*  返回数据类型:
`ToBytes()`, `ToString()`, `ToBase64String()`, `ToHexString()`

*  更多信息可以查看 [文档](docs/README.md)


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
