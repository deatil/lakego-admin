package crc16

import (
    "fmt"
    "strconv"
    "strings"
)

// 构造函数
func NewCRC16(params ...Params) *Table {
    return NewTable(params...)
}

// 构造函数
func NewCRC16Hash(params Params) Hash16 {
    table := &Table{}
    table.params = params

    return NewHash(table.MakeData())
}

// =======================

// 生成
func Checksum(data []byte, params Params) uint16 {
    return NewTable(params).Checksum(data)
}

// 生成 BUYPASS
func ChecksumBUYPASS(data []byte) uint16 {
    return NewTable(CRC16_BUYPASS).Checksum(data)
}

// 生成 MODBUS
func ChecksumMODBUS(data []byte) uint16 {
    return NewTable(CRC16_MODBUS).Checksum(data)
}

// 生成 X_25
func ChecksumX_25(data []byte) uint16 {
    return NewTable(CRC16_X_25).Checksum(data)
}

// 生成 XMODEM
func ChecksumXMODEM(data []byte) uint16 {
    return NewTable(CRC16_XMODEM).Checksum(data)
}

// 生成 CCITT
func ChecksumCCITT(data []byte) uint16 {
    return NewTable(CRC16_CCITT).Checksum(data)
}

// 生成 CCITT_FALSE
func ChecksumCCITT_FALSE(data []byte) uint16 {
    return NewTable(CRC16_CCITT_FALSE).Checksum(data)
}

// 生成 DNP
func ChecksumDNP(data []byte) uint16 {
    return NewTable(CRC16_DNP).Checksum(data)
}

// =======================

// 输出四位 16 进制字符
func ToHexString(data uint16) string {
    return fmt.Sprintf("%04X", data)
}

// 输出四位 16 进制字符，高低字节对调
func ToReverseHexString(data uint16) string {
    data = (data << 8) ^ (data >> 8)

    return fmt.Sprintf("%04X", data)
}

// 输出二进制字符
func ToBinString(data uint16) string {
    res := strconv.FormatInt(int64(data), 2)

    needStr := ""
    size := 16 - len(res)
    if size > 0 {
        needStr = strings.Repeat("0", size)
    }

    return needStr + res
}

// 输出二进制字符，高低字节对调
func ToReverseHexBinString(data uint16) string {
    data = (data << 8) ^ (data >> 8)

    res := strconv.FormatInt(int64(data), 2)

    needStr := ""
    size := 16 - len(res)
    if size > 0 {
        needStr = strings.Repeat("0", size)
    }

    return needStr + res
}
