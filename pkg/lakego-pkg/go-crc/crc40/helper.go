package crc40

import (
    "fmt"
)

// 构造函数
func NewCRC40(params ...Params) *CRC {
    return NewCRC(params...)
}

// Hash
func NewCRC40Hash(params Params) Hash40 {
    crc := NewCRC40(params).MakeTable()

    return NewHash(crc)
}

// =======================

// 生成
func Checksum(data []byte, params Params) uint64 {
    return NewCRC40(params).Checksum(data)
}

// 生成 GSM
func ChecksumGSM(data []byte) uint64 {
    return NewCRC40(CRC40_GSM).Checksum(data)
}

// =======================

// 输出 16 进制字符
func ToHexString(data uint64) string {
    res := fmt.Sprintf("%010X", data)

    return res[len(res) - 10:]
}

// 输出二进制字符
func ToBinString(data uint64) string {
    res := fmt.Sprintf("%040b", data)

    return res[len(res) - 40:]
}
