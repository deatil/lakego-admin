package crc32

import (
    "fmt"
)

// 构造函数
func NewCRC32(params ...Params) *CRC {
    return NewCRC(params...)
}

// Hash
func NewCRC32Hash(params Params) Hash32 {
    crc := NewCRC32(params).MakeTable()

    return NewHash(crc)
}

// =======================

// 生成
func Checksum(data []byte, params Params) uint32 {
    return NewCRC32(params).Checksum(data)
}

// 生成 CRC32
func ChecksumCRC32(data []byte) uint32 {
    return NewCRC32(CRC32).Checksum(data)
}

// 生成 MPEG_2
func ChecksumMPEG_2(data []byte) uint32 {
    return NewCRC32(CRC32_MPEG_2).Checksum(data)
}

// 生成 BZIP2
func ChecksumBZIP2(data []byte) uint32 {
    return NewCRC32(CRC32_BZIP2).Checksum(data)
}

// 生成 POSIX
func ChecksumPOSIX(data []byte) uint32 {
    return NewCRC32(CRC32_POSIX).Checksum(data)
}

// 生成 JAMCRC
func ChecksumJAMCRC(data []byte) uint32 {
    return NewCRC32(CRC32_JAMCRC).Checksum(data)
}

// 生成 CRC32A
func ChecksumCRC32A(data []byte) uint32 {
    return NewCRC32(CRC32_CRC32A).Checksum(data)
}

// 生成 IEEE
func ChecksumIEEE(data []byte) uint32 {
    return NewCRC32(CRC32_IEEE).Checksum(data)
}

// 生成 Castagnoli
func ChecksumCastagnoli(data []byte) uint32 {
    return NewCRC32(CRC32_Castagnoli).Checksum(data)
}

// 生成 CRC32C
func ChecksumCRC32C(data []byte) uint32 {
    return NewCRC32(CRC32_CRC32C).Checksum(data)
}

// 生成 Koopman
func ChecksumKoopman(data []byte) uint32 {
    return NewCRC32(CRC32_Koopman).Checksum(data)
}

// 生成 CKSUM
func ChecksumCKSUM(data []byte) uint32 {
    return NewCRC32(CRC32_CKSUM).Checksum(data)
}

// 生成 XFER
func ChecksumXFER(data []byte) uint32 {
    return NewCRC32(CRC32_XFER).Checksum(data)
}

// 生成 CRC32D
func ChecksumCRC32D(data []byte) uint32 {
    return NewCRC32(CRC32_CRC32D).Checksum(data)
}

// 生成 CRC32Q
func ChecksumCRC32Q(data []byte) uint32 {
    return NewCRC32(CRC32_CRC32Q).Checksum(data)
}

// =======================

// 输出 16 进制字符
func ToHexString(data uint32) string {
    return fmt.Sprintf("%08X", data)
}

// 输出 16 进制字符，高低字节对调
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
