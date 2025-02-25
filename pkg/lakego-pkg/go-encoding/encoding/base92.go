package encoding

import (
    "github.com/deatil/go-encoding/base92"
)

// Base92 Decode
func (this Encoding) Base92Decode() Encoding {
    data := string(this.data)
    this.data, this.Error = base92.StdEncoding.DecodeString(data)

    return this
}

// Base92 Encode
func (this Encoding) Base92Encode() Encoding {
    data := base92.StdEncoding.EncodeToString(this.data)
    this.data = []byte(data)

    return this
}
