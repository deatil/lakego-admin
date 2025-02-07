package encoding

import (
    "github.com/deatil/go-encoding/quotedprintable"
)

// quotedprintable Decode
func (this Encoding) QuotedprintableDecode() Encoding {
    this.data, this.Error = quotedprintable.StdEncoding.Decode(this.data)

    return this
}

// quotedprintable Encode
func (this Encoding) QuotedprintableEncode() Encoding {
    this.data, this.Error = quotedprintable.StdEncoding.Encode(this.data)

    return this
}
