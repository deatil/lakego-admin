package encoding

import (
    "github.com/deatil/go-encoding/base36"
)

// Decode Base36
func (this Encoding) Base36Decode() Encoding {
    data := string(this.data)
    this.data, this.Error = base36.StdEncoding.DecodeString(data)

    return this
}

// Encode Base36
func (this Encoding) Base36Encode() Encoding {
    data := base36.StdEncoding.EncodeToString(this.data)
    this.data = []byte(data)

    return this
}
