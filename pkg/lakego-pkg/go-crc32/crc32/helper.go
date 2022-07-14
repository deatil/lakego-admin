package crc32

import (
    "fmt"
)

// 构造函数
func NewCRC32(params ...Params) *Table {
    return NewTable(params...)
}

// Hash
func NewCRC32Hash(params Params) Hash32 {
    table := &Table{}
    table.params = params

    return NewHash(table.MakeData())
}

// =======================

// 生成
func Checksum(data []byte, params Params) uint32 {
    return NewTable(params).Checksum(data)
}

// 生成 CRC32
func ChecksumCRC32(data []byte) uint32 {
    return NewTable(CRC32).Checksum(data)
}

// 生成 MPEG_2
func ChecksumMPEG_2(data []byte) uint32 {
    return NewTable(CRC32_MPEG_2).Checksum(data)
}

// 生成 BZIP2
func ChecksumBZIP2(data []byte) uint32 {
    return NewTable(CRC32_BZIP2).Checksum(data)
}

// 生成 POSIX
func ChecksumPOSIX(data []byte) uint32 {
    return NewTable(CRC32_POSIX).Checksum(data)
}

// 生成 JAMCRC
func ChecksumJAMCRC(data []byte) uint32 {
    return NewTable(CRC32_JAMCRC).Checksum(data)
}

// 生成 CRC32A
func ChecksumCRC32A(data []byte) uint32 {
    return NewTable(CRC32_CRC32A).Checksum(data)
}

// 生成 IEEE
func ChecksumIEEE(data []byte) uint32 {
    return NewTable(CRC32_IEEE).Checksum(data)
}

// 生成 Castagnoli
func ChecksumCastagnoli(data []byte) uint32 {
    return NewTable(CRC32_Castagnoli).Checksum(data)
}

// 生成 CRC32C
func ChecksumCRC32C(data []byte) uint32 {
    return NewTable(CRC32_CRC32C).Checksum(data)
}

// 生成 Koopman
func ChecksumKoopman(data []byte) uint32 {
    return NewTable(CRC32_Koopman).Checksum(data)
}

// =======================

// 输出四位 16 进制字符
func ToHexString(data uint32) string {
    return fmt.Sprintf("%08X", data)
}

// 输出四位 16 进制字符，高低字节对调
func ToReverseHexString(data uint32) string {
    data = (data << 16) ^ (data >> 16)

    return fmt.Sprintf("%08X", data)
}

// 输出二进制字符
func ToBinString(data uint32) string {
    return fmt.Sprintf("%032b", data)
}

// 输出二进制字符，高低字节对调
func ToReverseHexBinString(data uint32) string {
    data = (data << 16) ^ (data >> 16)

    return fmt.Sprintf("%032b", data)
}
