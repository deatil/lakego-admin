package encoding

import (
    "bytes"
    "encoding/ascii85"
)

// Base85 编码
func Base85Encode(src string) string {
    text := []byte(src)

    dest := make([]byte, ascii85.MaxEncodedLen(len(text)))
    ascii85.Encode(dest, text)

    return string(dest)
}

// Base85 解码
func Base85Decode(s string) string {
    decodedText := make([]byte, len([]byte(s)))
    decoded, _, _ := ascii85.Decode(decodedText, []byte(s), true)
    decodedText = decodedText[:decoded]

    return string(bytes.Trim(decodedText, "\x00"))
}

// ====================

// Base85
func (this Encoding) FromBase85String(data string) Encoding {
    src := []byte(data)

    decodedText := make([]byte, len(src))
    decoded, _, err := ascii85.Decode(decodedText, src, true)
    if err != nil {
        this.Error = err
        return this
    }

    decodedText = decodedText[:decoded]

    this.data = bytes.Trim(decodedText, "\x00")

    return this
}

// Base85
func FromBase85String(data string) Encoding {
    return defaultEncode.FromBase85String(data)
}

// 输出 Base85
func (this Encoding) ToBase85String() string {
    text := this.data

    dest := make([]byte, ascii85.MaxEncodedLen(len(text)))
    ascii85.Encode(dest, text)

    return string(dest)
}
