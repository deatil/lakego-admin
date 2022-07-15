## crc 相关算法


### 项目介绍

*  crc 相关算法
*  可用检验方法：`Crc3`, `Crc4Itu`, `Crc5Epc`, `Crc5Itu`, `Crc5Usb`, `Crc6Itu`, `Crc7Mmc`, `BCC`, `LRC`
*  `crc24` 可用检验方法：`ChecksumCRC24`, `ChecksumFLEXRAY_A`, `ChecksumFLEXRAY_B`
*  `crc40` 可用检验方法：`ChecksumGSM`


### 下载安装

~~~go
go get -u github.com/deatil/go-crc
~~~


### 使用

~~~go
package main

import (
    "fmt"
    "encoding/hex"

    "github.com/deatil/go-crc/crc"
)

func main() {
    // 16进制字符转为 byte
    crcHex, _ := hex.DecodeString("020f")

    crcData := crc.Crc6Itu(crcHex)
    crcData2 := crc.ToHexString(crcData, "crc6")

    fmt.Println("计算结果为：", crcData2)
}
~~~


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
