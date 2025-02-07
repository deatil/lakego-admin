package encoding

import (
    "github.com/deatil/go-encoding/base45"
)

// Base45 Decode
func (this Encoding) Base45Decode() Encoding {
    decoded, err := base45.StdEncoding.DecodeString(string(this.data))

    this.data = decoded
    this.Error = err

    return this
}

// Base45 Encode
func (this Encoding) Base45Encode() Encoding {
    data := base45.StdEncoding.EncodeToString(this.data)
    this.data = []byte(data)

    return this
}
