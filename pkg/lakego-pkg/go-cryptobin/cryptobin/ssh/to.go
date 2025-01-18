package ssh

import (
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// output Key Bytes
func (this SSH) ToKeyBytes() []byte {
    return this.keyData
}

// output Key string
func (this SSH) ToKeyString() string {
    return string(this.keyData)
}

// ==========

// output Bytes
func (this SSH) ToBytes() []byte {
    return this.parsedData
}

// output string
func (this SSH) ToString() string {
    return string(this.parsedData)
}

// output Base64
func (this SSH) ToBase64String() string {
    return encoding.Base64Encode(this.parsedData)
}

// output Hex
func (this SSH) ToHexString() string {
    return encoding.HexEncode(this.parsedData)
}

// ==========

// output verify
func (this SSH) ToVerify() bool {
    return this.verify
}

// output verify int
func (this SSH) ToVerifyInt() int {
    if this.verify {
        return 1
    }

    return 0
}
