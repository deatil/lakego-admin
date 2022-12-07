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
