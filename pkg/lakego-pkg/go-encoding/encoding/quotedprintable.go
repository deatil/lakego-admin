package encoding

import (
    "github.com/deatil/go-encoding/quotedprintable"
)

// 解码 quotedprintable
func (this Encoding) QuotedprintableDecode() Encoding {
    this.data, this.Error = quotedprintable.StdEncoding.Decode(this.data)

    return this
}

// 编码 quotedprintable
func (this Encoding) QuotedprintableEncode() Encoding {
    this.data, this.Error = quotedprintable.StdEncoding.Encode(this.data)

    return this
}
