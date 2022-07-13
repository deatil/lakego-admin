package hash

import (
    "strconv"
    "hash/crc32"
)

// CRC32IEEE 哈希值
func CRC32IEEE(s string) string {
    data := []byte(s)

    res := crc32.ChecksumIEEE(data)

    return strconv.FormatInt(int64(res), 16)
}

// CRC32IEEE 哈希值
func (this Hash) CRC32IEEE() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return CRC32IEEE(newData), nil
    })
}

// =======================

// CRC32Castagnoli 哈希值
func CRC32Castagnoli(s string) string {
    data := []byte(s)

    tab := crc32.MakeTable(crc32.Castagnoli)
    res := crc32.Checksum(data, tab)

    return strconv.FormatInt(int64(res), 16)
}

// CRC32Castagnoli 哈希值
func (this Hash) CRC32Castagnoli() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return CRC32Castagnoli(newData), nil
    })
}

// =======================

// CRC32Koopman 哈希值
func CRC32Koopman(s string) string {
    data := []byte(s)

    tab := crc32.MakeTable(crc32.Koopman)
    res := crc32.Checksum(data, tab)

    return strconv.FormatInt(int64(res), 16)
}

// CRC32Koopman 哈希值
func (this Hash) CRC32Koopman() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return CRC32Koopman(newData), nil
    })
}
