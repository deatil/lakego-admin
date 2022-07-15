package crc40

import (
    "fmt"
)

// 构造函数
func NewCRC40(params ...Params) *Table {
    return NewTable(params...)
}

// Hash
func NewCRC40Hash(params Params) Hash40 {
    table := &Table{}
    table.params = params

    return NewHash(table.MakeData())
}

// =======================

// 生成
func Checksum(data []byte, params Params) uint64 {
    return NewTable(params).Checksum(data)
}

// 生成 GSM
func ChecksumGSM(data []byte) uint64 {
    return NewTable(CRC40_GSM).Checksum(data)
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
