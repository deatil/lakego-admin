package encoding

import (
    "github.com/deatil/go-encoding/base100"
)

// Base100
func (this Encoding) Base100Decode() Encoding {
    data := string(this.data)
    this.data, this.Error = base100.Decode(data)

    return this
}

// 编码 Base100
func (this Encoding) Base100Encode() Encoding {
    data := base100.Encode(this.data)
    this.data = []byte(data)

    return this
}
