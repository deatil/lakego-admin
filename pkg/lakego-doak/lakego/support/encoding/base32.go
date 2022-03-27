package encoding

import (
    "encoding/base32"
)

// Base32编码
func Base32Encode(str string) string {
    newStr := base32.StdEncoding.EncodeToString([]byte(str))
    return newStr
}

// Base32解码
func Base32Decode(str string) string {
    newStr, err := base32.StdEncoding.DecodeString(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}
