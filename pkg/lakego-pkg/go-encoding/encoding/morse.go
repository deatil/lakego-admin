package encoding

import (
    "github.com/deatil/go-encoding/morse"
)

// MorseITU
func (this Encoding) MorseITUDecode() Encoding {
    data := string(this.data)
    data, err := morse.DecodeITU(data)

    this.data = []byte(data)
    this.Error = err

    return this
}

// 编码 MorseITU
func (this Encoding) MorseITUEncode() Encoding {
    data := morse.EncodeITU(string(this.data))
    this.data = []byte(data)

    return this
}
