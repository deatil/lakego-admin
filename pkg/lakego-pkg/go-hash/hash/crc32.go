package hash

import (
    "strconv"
    "hash/crc32"
)

// CRC32 哈希值
func CRC32(s string) string {
    data := []byte(s)

    res := crc32.ChecksumIEEE(data)

    return strconv.FormatInt(int64(res), 16)
}

// CRC32 哈希值
func (this Hash) CRC32() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return CRC32(newData), nil
    })
}
