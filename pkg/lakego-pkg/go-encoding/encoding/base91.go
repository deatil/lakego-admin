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

// ====================

// Base91
func (this Encoding) FromBase91String(data string) Encoding {
    this.data, this.Error = base91.StdEncoding.DecodeString(data)

    return this
}

// Base91
func FromBase91String(data string) Encoding {
    return defaultEncode.FromBase91String(data)
}

// 输出 Base91
func (this Encoding) ToBase91String() string {
    return base91.StdEncoding.EncodeToString(this.data)
}
