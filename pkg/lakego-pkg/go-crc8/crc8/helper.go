package crc8

import (
    "fmt"
)

// 输出 16 进制字符
func ToHexString(data uint16) string {
    return fmt.Sprintf("%04X", data)
}

// 输出 16 进制字符，高低字节对调
func ToHeightHexString(data uint16) string {
    data = (data << 8) ^ (data >> 8)

    return fmt.Sprintf("%04X", data)
}

// 构造函数
func NewCRC8(params ...Params) *Table {
    return NewTable(params...)
}

// 生成
func Checksum(data []byte, params Params) uint8 {
    return NewTable(params).Checksum(data)
}

// 生成 CRC8
func ChecksumCRC8(data []byte) uint8 {
    return NewTable(CRC8).Checksum(data)
}

// 生成 WCDMA
func ChecksumWCDMA(data []byte) uint8 {
    return NewTable(CRC8_WCDMA).Checksum(data)
}
