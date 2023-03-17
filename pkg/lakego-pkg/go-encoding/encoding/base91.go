package encoding

import (
    "github.com/deatil/go-encoding/base91"
)

// Base91
func (this Encoding) Base91Decode() Encoding {
    data := string(this.data)
    this.data, this.Error = base91.StdEncoding.DecodeString(data)

    return this
}

// 编码 Base91
func (this Encoding) Base91Encode() Encoding {
    data := base91.StdEncoding.EncodeToString(this.data)
    this.data = []byte(data)

    return this
}
