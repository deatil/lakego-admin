package crc32

import (
    "fmt"
)

// 构造函数
func NewCRC32(params ...Params) *Table {
    return NewTable(params...)
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
