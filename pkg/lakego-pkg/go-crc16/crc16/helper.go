package crc16

import (
    "fmt"
)

// 构造函数
func NewCRC16(params ...Params) *CRC {
    return NewCRC(params...)
}

// 构造函数
func NewCRC16Hash(params Params) Hash16 {
    crc := NewCRC16(params).MakeTable()

    return NewHash(crc)
}

// =======================

// 生成
func Checksum(data []byte, params Params) uint16 {
    return NewCRC16(params).Checksum(data)
}

// 生成 IBM
func ChecksumIBM(data []byte) uint16 {
    return NewCRC16(CRC16_IBM).Checksum(data)
}

// 生成 ARC
func ChecksumARC(data []byte) uint16 {
    return NewCRC16(CRC16_ARC).Checksum(data)
}

// 生成 AUG_CCITT
func ChecksumAUG_CCITT(data []byte) uint16 {
    return NewCRC16(CRC16_AUG_CCITT).Checksum(data)
}

// 生成 BUYPASS
func ChecksumBUYPASS(data []byte) uint16 {
    return NewCRC16(CRC16_BUYPASS).Checksum(data)
}

// 生成 CCITT
func ChecksumCCITT(data []byte) uint16 {
    return NewCRC16(CRC16_CCITT).Checksum(data)
}

// 生成 CCITT_FALSE
func ChecksumCCITT_FALSE(data []byte) uint16 {
    return NewCRC16(CRC16_CCITT_FALSE).Checksum(data)
}

// 生成 CDMA2000
func ChecksumCDMA2000(data []byte) uint16 {
    return NewCRC16(CRC16_CDMA2000).Checksum(data)
}

// 生成 DDS_110
func ChecksumDDS_110(data []byte) uint16 {
    return NewCRC16(CRC16_DDS_110).Checksum(data)
}

// 生成 DECT_R
func ChecksumDECT_R(data []byte) uint16 {
    return NewCRC16(CRC16_DECT_R).Checksum(data)
}

// 生成 DECT_X
func ChecksumDECT_X(data []byte) uint16 {
    return NewCRC16(CRC16_DECT_X).Checksum(data)
}

// 生成 DNP
func ChecksumDNP(data []byte) uint16 {
    return NewCRC16(CRC16_DNP).Checksum(data)
}

// 生成 GENIBUS
func ChecksumGENIBUS(data []byte) uint16 {
    return NewCRC16(CRC16_GENIBUS).Checksum(data)
}

// 生成 MAXIM
func ChecksumMAXIM(data []byte) uint16 {
    return NewCRC16(CRC16_MAXIM).Checksum(data)
}

// 生成 MCRF4XX
func ChecksumMCRF4XX(data []byte) uint16 {
    return NewCRC16(CRC16_MCRF4XX).Checksum(data)
}

// 生成 RIELLO
func ChecksumRIELLO(data []byte) uint16 {
    return NewCRC16(CRC16_RIELLO).Checksum(data)
}

// 生成 T10_DIF
func ChecksumT10_DIF(data []byte) uint16 {
    return NewCRC16(CRC16_T10_DIF).Checksum(data)
}

// 生成 TELEDISK
func ChecksumTELEDISK(data []byte) uint16 {
    return NewCRC16(CRC16_TELEDISK).Checksum(data)
}

// 生成 TMS37157
func ChecksumTMS37157(data []byte) uint16 {
    return NewCRC16(CRC16_TMS37157).Checksum(data)
}

// 生成 USB
func ChecksumUSB(data []byte) uint16 {
    return NewCRC16(CRC16_USB).Checksum(data)
}

// 生成 CRC_A
func ChecksumCRC_A(data []byte) uint16 {
    return NewCRC16(CRC16_CRC_A).Checksum(data)
}

// 生成 KERMIT
func ChecksumKERMIT(data []byte) uint16 {
    return NewCRC16(CRC16_KERMIT).Checksum(data)
}

// 生成 MODBUS
func ChecksumMODBUS(data []byte) uint16 {
    return NewCRC16(CRC16_MODBUS).Checksum(data)
}

// 生成 X_25
func ChecksumX_25(data []byte) uint16 {
    return NewCRC16(CRC16_X_25).Checksum(data)
}

// 生成 XMODEM
func ChecksumXMODEM(data []byte) uint16 {
    return NewCRC16(CRC16_XMODEM).Checksum(data)
}

// 生成 XMODEM2
func ChecksumXMODEM2(data []byte) uint16 {
    return NewCRC16(CRC16_XMODEM2).Checksum(data)
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
    return fmt.Sprintf("%016b", data)
}

// 输出二进制字符，高低字节对调
func ToReverseHexBinString(data uint16) string {
    data = (data << 8) ^ (data >> 8)

    return fmt.Sprintf("%016b", data)
}
