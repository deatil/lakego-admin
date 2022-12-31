package encoding

import (
    "github.com/deatil/go-encoding/morse"
)

// 加密
func MorseITUEncode(str string) string {
    return morse.EncodeITU(str)
}

// 解密
func MorseITUDecode(str string) string {
    newStr, err := morse.DecodeITU(str)
    if err != nil {
        return ""
    }

    return newStr
}

// ====================

// MorseITU
func (this Encoding) FromMorseITUString(data string) Encoding {
    data, err := morse.DecodeITU(data)

    this.data = []byte(data)
    this.Error = err

    return this
}

// MorseITU
func FromMorseITUString(data string) Encoding {
    return defaultEncode.FromMorseITUString(data)
}

// 输出 MorseITU
func (this Encoding) ToMorseITUString() string {
    return morse.EncodeITU(string(this.data))
}
