package curve25519

import (
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
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
    return cryptobin_tool.NewEncoding().Base64Encode(this.secretData)
}

// 输出Hex
func (this Curve25519) ToHexString() string {
    return cryptobin_tool.NewEncoding().HexEncode(this.secretData)
}
