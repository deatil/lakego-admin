package encoding

import (
    "github.com/deatil/go-encoding/base45"
)

// Base45 编码
func Base45Encode(str string) string {
    return base45.Encode(str)
}

// Base45 解码
func Base45Decode(str string) string {
    decoded, err := base45.Decode(str)
    if err != nil {
        return ""
    }

    return decoded
}
