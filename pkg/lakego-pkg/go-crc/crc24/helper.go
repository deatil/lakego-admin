package crc24

import (
    "fmt"
)

// 构造函数
func NewCRC24(params ...Params) *Table {
    return NewTable(params...)
}

// Hash
func NewCRC24Hash(params Params) Hash24 {
    table := &Table{}
    table.params = params

    return NewHash(table.MakeData())
}

// =======================

// 生成
func Checksum(data []byte, params Params) uint32 {
    return NewTable(params).Checksum(data)
}

// 生成 CRC24
func ChecksumCRC24(data []byte) uint32 {
    return NewTable(CRC24).Checksum(data)
}

// 生成 FLEXRAY_A
func ChecksumFLEXRAY_A(data []byte) uint32 {
    return NewTable(CRC24_FLEXRAY_A).Checksum(data)
}

// 生成 FLEXRAY_B
func ChecksumFLEXRAY_B(data []byte) uint32 {
    return NewTable(CRC24_FLEXRAY_B).Checksum(data)
}

// =======================

// 输出 16 进制字符
func ToHexString(data uint32) string {
    res := fmt.Sprintf("%06X", data)

    return res[len(res) - 6:]
}

// 输出二进制字符
func ToBinString(data uint32) string {
    res := fmt.Sprintf("%024b", data)

    return res[len(res) - 24:]
}
