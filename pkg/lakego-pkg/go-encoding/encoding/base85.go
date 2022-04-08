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
