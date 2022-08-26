package crc12

import (
    "fmt"
    "encoding/hex"
)

// 构造函数
func NewCRC12(params ...Params) *CRC {
    return NewCRC(params...)
}

// Hash
func NewCRC12Hash(params Params) Hash12 {
    crc := NewCRC12(params).MakeTable()

    return NewHash(crc)
}

// =======================

// 生成
func Checksum(data []byte, params Params) uint16 {
    return NewCRC12(params).Checksum(data)
}

// 生成 CRC12
// 31303432 => 3CD
func ChecksumCRC12(data []byte) uint16 {
    return NewCRC12(CRC12).Checksum(data)
}

// =======================

// 输出 16 进制字符
func ToHexString(data uint16) string {
    res := fmt.Sprintf("%03X", data)

    return res[len(res) - 3:]
}

// 输出 16 进制字符
func ToHexStringFromBytes(data []byte) string {
    res := hex.EncodeToString(data)

    return res[len(res) - 3:]
}

// 输出二进制字符
func ToBinString(data uint16) string {
    res := fmt.Sprintf("%012b", data)

    return res[len(res) - 12:]
}
