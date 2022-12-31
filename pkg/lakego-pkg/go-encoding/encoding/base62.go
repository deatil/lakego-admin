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

// ====================

// Base62
func (this Encoding) FromBase62String(data string) Encoding {
    this.data, this.Error = base62.StdEncoding.DecodeString(data)

    return this
}

// Base62
func FromBase62String(data string) Encoding {
    return defaultEncode.FromBase62String(data)
}

// 输出 Base62
func (this Encoding) ToBase62String() string {
    return base62.StdEncoding.EncodeToString(this.data)
}
