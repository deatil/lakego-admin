package hash

import (
    "strconv"
    "hash/crc64"
)

// CRC64ISO
func CRC64ISO(s string) string {
    data := []byte(s)

    tab := crc64.MakeTable(crc64.ISO)
    res := crc64.Checksum(data, tab)

    return strconv.FormatInt(int64(res), 16)
}

// CRC64ISO
func (this Hash) CRC64ISO() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return CRC64ISO(newData), nil
    })
}

// =======================

// CRC64ECMA 哈希值
func CRC64ECMA(s string) string {
    data := []byte(s)

    tab := crc64.MakeTable(crc64.ECMA)
    res := crc64.Checksum(data, tab)

    return strconv.FormatInt(int64(res), 16)
}

// CRC64ECMA 哈希值
func (this Hash) CRC64ECMA() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return CRC64ECMA(newData), nil
    })
}
