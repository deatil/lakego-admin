package encoding

import (
    "bytes"
    "encoding/ascii85"
)

// Base85
func (this Encoding) Base85Decode() Encoding {
    src := this.data

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

// 编码 Base85
func (this Encoding) Base85Encode() Encoding {
    text := this.data

    dest := make([]byte, ascii85.MaxEncodedLen(len(text)))
    ascii85.Encode(dest, text)

    this.data = dest

    return this
}
