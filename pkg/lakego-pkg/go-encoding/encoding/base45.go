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

// ====================

// Base45
func (this Encoding) FromBase45String(data string) Encoding {
    decoded, err := base45.Decode(data)

    this.data = []byte(decoded)
    this.Error = err

    return this
}

// Base45
func FromBase45String(data string) Encoding {
    return defaultEncode.FromBase45String(data)
}

// 输出 Base45
func (this Encoding) ToBase45String() string {
    return base45.Encode(string(this.data))
}
