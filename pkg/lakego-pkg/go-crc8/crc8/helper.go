package crc8

import (
    "fmt"
    "strconv"
    "strings"
)

// 构造函数
func NewCRC8(params ...Params) *Table {
    return NewTable(params...)
}

// =======================

// 生成
func Checksum(data []byte, params Params) uint8 {
    return NewTable(params).Checksum(data)
}

// 生成 CRC8
func ChecksumCRC8(data []byte) uint8 {
    return NewTable(CRC8).Checksum(data)
}

// 生成 ITU
func ChecksumITU(data []byte) uint8 {
    return NewTable(CRC8_ITU).Checksum(data)
}

// 生成 MAXIM
func ChecksumMAXIM(data []byte) uint8 {
    return NewTable(CRC8_MAXIM).Checksum(data)
}

// 生成 ROHC
func ChecksumROHC(data []byte) uint8 {
    return NewTable(CRC8_ROHC).Checksum(data)
}

// =======================

// 输出两位 16 进制字符
func ToHexString(data uint8) string {
    return fmt.Sprintf("%02X", data)
}

// 输出两位 16 进制字符，高低字节对调
func ToReverseHexString(data uint8) string {
    data = (data << 8) ^ (data >> 8)

    return fmt.Sprintf("%02X", data)
}

// 输出二进制字符
func ToBinString(data uint8) string {
    res := strconv.FormatInt(int64(data), 2)

    needStr := ""
    size := 8 - len(res)
    if size > 0 {
        needStr = strings.Repeat("0", size)
    }

    return needStr + res
}

// 输出二进制字符，高低字节对调
func ToReverseHexBinString(data uint8) string {
    data = (data << 8) ^ (data >> 8)

    res := strconv.FormatInt(int64(data), 2)

    needStr := ""
    size := 8 - len(res)
    if size > 0 {
        needStr = strings.Repeat("0", size)
    }

    return needStr + res
}
