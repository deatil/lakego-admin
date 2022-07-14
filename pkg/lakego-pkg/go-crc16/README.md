## crc16


### 项目介绍

*  crc16 相关算法
*  可用检验方法：`ChecksumIBM`, `ChecksumARC`, `ChecksumAUG_CCITT`, `ChecksumBUYPASS`, `ChecksumCCITT`, `ChecksumCCITT_FALSE`, `ChecksumCDMA2000`, `ChecksumDDS_110`, `ChecksumDECT_R`, `ChecksumDECT_X`, `ChecksumDNP`, `ChecksumGENIBUS`, `ChecksumMAXIM`, `ChecksumMCRF4XX`, `ChecksumRIELLO`, `ChecksumT10_DIF`, `ChecksumTELEDISK`, `ChecksumTMS37157`, `ChecksumUSB`, `ChecksumCRC_A`, `ChecksumKERMIT`, `ChecksumMODBUS`, `ChecksumX_25`, `ChecksumXMODEM`, `ChecksumXMODEM2`


### 下载安装

~~~go
go get -u github.com/deatil/go-crc16
~~~


### 使用

~~~go
package main

import (
    "fmt"
    "encoding/hex"

    "github.com/deatil/go-crc16/crc16"
)

func main() {
    // 16进制字符转为 byte
    crc16Hex, _ := hex.DecodeString("0100")
    // encodedStr := hex.EncodeToString(b)

    crc16Data := crc16.ChecksumMODBUS(crc16Hex)
    crc16Data2 := crc16.ToHexString(crc16Data)
    // crc16Data2 := crc16.ToReverseHexString(crc16Data)

    fmt.Println("计算结果为：", crc16Data2)

    // hash
    crc16Hash := crc16.NewCRC16Hash(crc16.CRC16_MODBUS)
    crc16Hash.Write(crc16Hex)
    crc16HashData := crc16Hash.Sum(nil)
    crc16HashData2 := hex.EncodeToString(crc16HashData)

    fmt.Println("hash结果为：", crc16HashData2)
}
~~~


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
