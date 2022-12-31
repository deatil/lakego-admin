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

// ====================

// Base100
func (this Encoding) FromBase100String(data string) Encoding {
    this.data, this.Error = base100.Decode(data)

    return this
}

// Base100
func FromBase100String(data string) Encoding {
    return defaultEncode.FromBase100String(data)
}

// 输出 Base100
func (this Encoding) ToBase100String() string {
    return base100.Encode(this.data)
}
