package encoding

import (
    "github.com/deatil/go-encoding/puny"
)

// PunyDecode
func (this Encoding) PunyDecode() Encoding {
    this.data, this.Error = puny.StdEncoding.Decode(this.data)

    return this
}

// 编码 Puny
func (this Encoding) PunyEncode() Encoding {
    this.data, this.Error = puny.StdEncoding.Encode(this.data)

    return this
}
