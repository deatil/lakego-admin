## crc32


### 项目介绍

*  crc32 相关算法
*  可用检验方法：`ChecksumCRC32`, `ChecksumMPEG_2`, `ChecksumBZIP2`, `ChecksumPOSIX`, `ChecksumJAMCRC`, `ChecksumCRC32A`, `ChecksumIEEE`, `ChecksumCastagnoli`, `ChecksumCRC32C`, `ChecksumKoopman`, `ChecksumCKSUM`, `ChecksumXFER`, `ChecksumCRC32D`, `ChecksumCRC32Q`


### 下载安装

~~~go
go get -u github.com/deatil/go-crc32
~~~


### 使用

~~~go
package main

import (
    "fmt"
    "encoding/hex"

    "github.com/deatil/go-crc32/crc32"
)

func main() {
    // 16进制字符转为 byte
    crc32Hex, _ := hex.DecodeString("020f")

    crc32Data := crc32.ChecksumMPEG_2(crc32Hex)
    crc32Data2 := crc32.ToHexString(crc32Data)

    fmt.Println("计算结果为：", crc32Data2)
}
~~~


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
