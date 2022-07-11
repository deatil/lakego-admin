package crc16

// 构造函数
func NewCRC16(params ...Params) *Table {
    return NewTable(params...)
}

// 构造函数
func NewCRC16Hash(params Params) Hash16 {
    table := &Table{}
    table.params = params

    return NewHash(table.MakeData())
}

// 生成
func Checksum(data []byte, params Params) uint16 {
    return NewTable(params).Checksum(data)
}

// 生成 BUYPASS
func ChecksumBUYPASS(data []byte) uint16 {
    return NewTable(CRC16_BUYPASS).Checksum(data)
}

// 生成 MODBUS
func ChecksumMODBUS(data []byte) uint16 {
    return NewTable(CRC16_MODBUS).Checksum(data)
}

// 生成 X_25
func ChecksumX_25(data []byte) uint16 {
    return NewTable(CRC16_X_25).Checksum(data)
}

// 生成 XMODEM
func ChecksumXMODEM(data []byte) uint16 {
    return NewTable(CRC16_XMODEM).Checksum(data)
}
