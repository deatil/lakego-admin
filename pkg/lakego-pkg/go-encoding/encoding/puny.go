package encoding

import (
    "github.com/deatil/go-encoding/puny"
)

// PunyDecode Decode
func (this Encoding) PunyDecode() Encoding {
    this.data, this.Error = puny.StdEncoding.Decode(this.data)

    return this
}

// Puny Encode
func (this Encoding) PunyEncode() Encoding {
    this.data, this.Error = puny.StdEncoding.Encode(this.data)

    return this
}
