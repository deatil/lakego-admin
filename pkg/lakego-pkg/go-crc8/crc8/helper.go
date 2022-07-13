package crc8

import (
    "fmt"
)

// 构造函数
func NewCRC8(params ...Params) *Table {
    return NewTable(params...)
}

// Hash
func NewCRC8Hash(params Params) Hash8 {
    table := &Table{}
    table.params = params

    return NewHash(table.MakeData())
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

// 生成 CDMA2000
func ChecksumCDMA2000(data []byte) uint8 {
    return NewTable(CRC8_CDMA2000).Checksum(data)
}

// 生成 DARC
func ChecksumDARC(data []byte) uint8 {
    return NewTable(CRC8_DARC).Checksum(data)
}

// 生成 DVB_S2
func ChecksumDVB_S2(data []byte) uint8 {
    return NewTable(CRC8_DVB_S2).Checksum(data)
}

// 生成 EBU
func ChecksumEBU(data []byte) uint8 {
    return NewTable(CRC8_EBU).Checksum(data)
}

// 生成 I_CODE
func ChecksumI_CODE(data []byte) uint8 {
    return NewTable(CRC8_I_CODE).Checksum(data)
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

// 生成 WCDMA
func ChecksumWCDMA(data []byte) uint8 {
    return NewTable(CRC8_WCDMA).Checksum(data)
}

// =======================

// 输出两位 16 进制字符
func ToHexString(data uint8) string {
    return fmt.Sprintf("%02X", data)
}

// 输出两位 16 进制字符，高低字节对调
func ToReverseHexString(data uint8) string {
    data = (data << 4) ^ (data >> 4)

    return fmt.Sprintf("%02X", data)
}

// 输出二进制字符
func ToBinString(data uint8) string {
    return fmt.Sprintf("%08b", data)
}

// 输出二进制字符，高低字节对调
func ToReverseHexBinString(data uint8) string {
    data = (data << 4) ^ (data >> 4)

    return fmt.Sprintf("%08b", data)
}
