package encoding

import (
    "github.com/deatil/go-encoding/basex"
)

// 加密
func Base2Encode(str string) string {
    return basex.Base2Encoding.Encode([]byte(str))
}

// 解密
func Base2Decode(str string) string {
    newStr, err := basex.Base2Encoding.Decode(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}

// =============================

// 加密
func Base16Encode(str string) string {
    return basex.Base16Encoding.Encode([]byte(str))
}

// 解密
func Base16Decode(str string) string {
    newStr, err := basex.Base16Encoding.Decode(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}

// =============================

// 加密
func Basex62Encode(str string) string {
    return basex.Base62Encoding.Encode([]byte(str))
}

// 解密
func Basex62Decode(str string) string {
    newStr, err := basex.Base62Encoding.Decode(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}

// ====================

// Basex2
func (this Encoding) FromBasex2String(data string) Encoding {
    this.data, this.Error = basex.Base2Encoding.Decode(data)

    return this
}

// Basex2
func FromBasex2String(data string) Encoding {
    return defaultEncode.FromBasex2String(data)
}

// Basex16
func (this Encoding) FromBasex16String(data string) Encoding {
    this.data, this.Error = basex.Base16Encoding.Decode(data)

    return this
}

// Base16
func FromBasex16String(data string) Encoding {
    return defaultEncode.FromBasex16String(data)
}

// Basex62
func (this Encoding) FromBasex62String(data string) Encoding {
    this.data, this.Error = basex.Base62Encoding.Decode(data)

    return this
}

// Basex62
func FromBasex62String(data string) Encoding {
    return defaultEncode.FromBasex62String(data)
}

// FromBasexEncoderString
func (this Encoding) FromBasexEncoderString(data string, encoder string) Encoding {
    this.data, this.Error = basex.NewEncoding(encoder).Decode(data)

    return this
}

// FromBasexEncoderString
func FromBasexEncoderString(data string, encode string) Encoding {
    return defaultEncode.FromBasexEncoderString(data, encode)
}

// ====================

// 输出 Base2
func (this Encoding) ToBase2String() string {
    return basex.Base2Encoding.Encode(this.data)
}

// 输出 Base16
func (this Encoding) ToBase16String() string {
    return basex.Base16Encoding.Encode(this.data)
}

// 输出 Basex62
func (this Encoding) ToBasex62String() string {
    return basex.Base62Encoding.Encode(this.data)
}

// 输出 BasexEncoder
func (this Encoding) ToBasexEncoderString(encoder string) string {
    return basex.NewEncoding(encoder).Encode(this.data)
}
