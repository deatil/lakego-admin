package encoding

import (
    "github.com/deatil/go-encoding/base91"
)

// 加密
func Base91Encode(str string) string {
    return base91.StdEncoding.EncodeToString([]byte(str))
}

// 解密
func Base91Decode(str string) string {
    newStr, err := base91.StdEncoding.DecodeString(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}
