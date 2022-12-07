## 编码算法


### 项目介绍

*  常用的编码算法


### 下载安装

~~~go
go get -u github.com/deatil/go-encoding
~~~


### 使用

~~~go
package main

import (
    "fmt"
    "github.com/deatil/go-encoding/encoding"
)

func main() {
	oldData := "useData"

    // Base32 编码
    base32Data := encoding.FromString(oldData).ToBase32String()
    fmt.Println("Base32 编码为：", base32Data)

    // Base64 编码
    base64Data := encoding.FromString(oldData).ToBase64String()
    fmt.Println("Base64 编码为：", base64Data)

	// =========================

    // Base32 解码
    base32DecodeData := encoding.FromBase32String(base32Data).ToString()
    fmt.Println("Base32 解码为：", base32DecodeData)

    // Base64 解码
    base64DecodeData := encoding.FromBase64String(base64Data).ToString()
    fmt.Println("Base64 解码为：", base64DecodeData)
}
~~~


### 使用方法

~~~go
	base64Data := encoding.
		FromString(oldData). // 数据来源
		ToBase64String()     // 输出结果，可为编码或者原始数据
~~~



### 输入输出数据

*  输入数据:
`FromBytes(data []byte)`, `FromString(data string)`
*  输出数据:
`ToBytes()`, `ToString()`, `String()`


### 常用解码编码

*  常用解码:
`FromBase32String(data string)`, `FromBase32HexString(data string)`, `FromBase32EncoderString(data string, encoder string)`, `FromBase58String(data string)`, `FromBase64String(data string)`, `FromBase64URLString(data string)`, `FromBase64RawString(data string)`, `FromBase64RawURLString(data string)`, `FromBase64SegmentString(data string)`, `FromBase64EncoderString(data string, encoder string) `, `FromBase85String(data string)`, `FromBase2String(data string)`, `FromBase16String(data string)`, `FromBasex62String(data string)`, `FromBasexEncoderString(data string, encoder string)`, `FromBase62String(data string)`, `FromBase91String(data string)`, `FromBase100String(data string)`, `FromMorseITUString(data string)`, `FromHexString(data string)`
*  常用编码:
`ToBase32String()`, `ToBase32HexString()`, `ToBase32EncoderString(encoder string)`, `ToBase58String()`, `ToBase64String()`, `ToBase64URLString()`, `ToBase64RawString()`, `ToBase64RawURLString()`, `ToBase64SegmentString()`, `ToBase64EncoderString(encoder string)`, `ToBase85String()`, `ToBase2String()`, `ToBase16String()`, `ToBasex62String()`, `ToBasexEncoderString(encoder string)`, `ToBase62String()`, `ToBase91String()`, `ToBase100String()`, `ToMorseITUString()`, `ToHexString()`


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
