package encoding

import (
    "github.com/deatil/go-encoding/base45"
)

// Base45
func (this Encoding) Base45Decode() Encoding {
    data := string(this.data)
    decoded, err := base45.Decode(data)

    this.data = []byte(decoded)
    this.Error = err

    return this
}

// 编码 Base45
func (this Encoding) Base45Encode() Encoding {
    data := base45.Encode(string(this.data))
    this.data = []byte(data)

    return this
}
