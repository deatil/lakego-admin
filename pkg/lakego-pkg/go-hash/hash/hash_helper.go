package hash

import (
    "strings"
)

// MD5_16
func MD5_16(s string) string {
    data := FromString(s).MD5().ToHexString()

    return data[8:24]
}

// CRC 左侧补码 0
func LeftCRCPadding(text string, size int) string {
    n := len(text)
    if n == 0 || size < 1 {
        return text
    }

    paddingSize := size - n%size

    // 为 0 时不补位
    if paddingSize == size {
        return text
    }

    paddingText := strings.Repeat("0", paddingSize)

    return paddingText + text
}
