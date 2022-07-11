package crc8

// 构造函数
func NewCRC8(params ...Params) *Table {
    return NewTable(params...)
}

// 生成
func Checksum(data []byte, params Params) uint8 {
    return NewTable(params).Checksum(data)
}

// 生成 CRC8
func ChecksumCRC8(data []byte) uint8 {
    return NewTable(CRC8).Checksum(data)
}

// 生成 WCDMA
func ChecksumWCDMA(data []byte) uint8 {
    return NewTable(CRC8_WCDMA).Checksum(data)
}
