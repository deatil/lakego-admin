## crc8


### 项目介绍

*  crc8 相关算法
*  可用检验方法：`ChecksumCRC8`, `ChecksumCDMA2000`, `ChecksumDARC`, `ChecksumDVB_S2`, `ChecksumEBU`, `ChecksumI_CODE`, `ChecksumITU`, `ChecksumMAXIM`, `ChecksumROHC`, `ChecksumWCDMA`


### 下载安装

~~~go
go get -u github.com/deatil/go-crc8
~~~


### 使用

~~~go
package main

import (
    "fmt"
    "encoding/hex"

    "github.com/deatil/go-crc8/crc8"
)

func main() {
    // 16进制字符转为 byte
    crc8Hex, _ := hex.DecodeString("010f")

    crc8Data := crc8.ChecksumMAXIM(crc8Hex)
    crc8Data2 := crc8.ToHexString(crc8Data)

    fmt.Println("计算结果为：", crc8Data2)
}
~~~


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
