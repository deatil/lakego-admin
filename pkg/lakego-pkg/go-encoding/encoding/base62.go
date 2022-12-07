package encoding

import (
    "github.com/deatil/go-encoding/base62"
)

// 加密
func Base62Encode(str string) string {
    return base62.StdEncoding.EncodeToString([]byte(str))
}

// 解密
func Base62Decode(str string) string {
    newStr, err := base62.StdEncoding.DecodeString(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}
