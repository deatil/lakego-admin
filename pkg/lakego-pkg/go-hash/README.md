## 摘要算法


### 项目介绍

*  常用的摘要 `hash` 算法
*  算法包括: `MD2`, `MD4`, `MD5`, `MD5SHA1`, `Ripemd160`, `SHA1`, `SHA256`, `SM3(国密)`


### 下载安装

~~~go
go get -u github.com/deatil/go-hash
~~~


### 使用

~~~go
package main

import (
    "fmt"
    "github.com/deatil/go-hash/hash"
)

func main() {
    // MD5 获取摘要
    md5Data := hash.
        FromString("useData").
        MD5().
        ToHexString()

    fmt.Println("MD5 结果：", md5Data)

    // MD5 获取摘要2
    md5Data2 := hash.
        NewMD5().
        Write([]byte("useData")).
        Sum(nil).
        ToHexString()

    fmt.Println("MD5 结果2：", md5Data2)
}

~~~


### 输入输出数据

*  输入数据:
`FromBytes(data []byte)`, `FromString(data string)`, `FromBase64String(data string)`, `FromHexString(data string)`, `FromReader(reader io.Reader)`
*  输出数据:
`String() string`, `ToBytes() []byte`, `ToString() string`, `ToBase64String() string`, `ToHexString() string`, `ToReader() io.Reader`


### 常用算法

*  常用算法:
`Blake2b_256()`, `Blake2b_384()`, `Blake2b_512()`, `Blake2s_256()`, `Blake2s_128()`, `MD2()`, `MD4()`, `MD5()`, `Ripemd160()`, `SHA1()`, `SHA224()`, `SHA256()`, `SHA384()`, `SHA512()`, `SHA512_224()`, `SHA512_256()`, `SHA3_224()`, `SHA3_256()`, `SHA3_384()`, `SHA3_512()`, `SHA3_512()`, `Shake128()`, `Shake256()`, `SM3()`, `Maphash()`, `Keccak256()`, `Keccak512()`, `HmacMd5(secret []byte)`, `HmacSHA1(secret []byte)`


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
