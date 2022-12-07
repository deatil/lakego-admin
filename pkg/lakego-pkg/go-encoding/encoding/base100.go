package encoding

import (
    "github.com/deatil/go-encoding/base100"
)

// 加密
func Base100Encode(str string) string {
    return base100.Encode([]byte(str))
}

// 解密
func Base100Decode(str string) string {
    newStr, err := base100.Decode(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}
