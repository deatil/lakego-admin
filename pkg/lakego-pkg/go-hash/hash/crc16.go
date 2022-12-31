package hash

import (
    "github.com/deatil/go-hash/crc16/x25"
    "github.com/deatil/go-hash/crc16/modbus"
)

// CRC16 / x25
func CRC16X25(s string) string {
    return x25.CRC16X25(s)
}

// CRC16_X25 哈希值
func (this Hash) CRC16X25() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return CRC16X25(newData), nil
    })
}

// CRC16 / modbus
func CRC16Modbus(s string) string {
    return modbus.CRC16Modbus(s)
}

// CRC16_Modbus 哈希值
func (this Hash) CRC16Modbus() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return CRC16Modbus(newData), nil
    })
}
