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
