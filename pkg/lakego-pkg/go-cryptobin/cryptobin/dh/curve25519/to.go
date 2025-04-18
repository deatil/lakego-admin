package curve25519

import (
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// 私钥/公钥
func (this Curve25519) ToKeyBytes() []byte {
    return this.keyData
}

// 私钥/公钥
func (this Curve25519) ToKeyString() string {
    return string(this.keyData)
}

// =================

// 输出字节
func (this Curve25519) ToBytes() []byte {
    return this.secretData
}

// 输出字符
func (this Curve25519) ToString() string {
    return string(this.secretData)
}

// 输出Base64
func (this Curve25519) ToBase64String() string {
    return encoding.Base64Encode(this.secretData)
}

// 输出Hex
func (this Curve25519) ToHexString() string {
    return encoding.HexEncode(this.secretData)
}
