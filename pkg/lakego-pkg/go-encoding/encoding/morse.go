package encoding

import (
    "github.com/deatil/go-encoding/morse"
)

// MorseITU Decode
func (this Encoding) MorseITUDecode() Encoding {
    data, err := morse.ITUEncoding.DecodeString(string(this.data))

    this.data = data
    this.Error = err

    return this
}

// MorseITU Encode
func (this Encoding) MorseITUEncode() Encoding {
    data := morse.ITUEncoding.EncodeToString(this.data)
    this.data = []byte(data)

    return this
}
