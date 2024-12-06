package dh

import (
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// 私钥/公钥
func (this DH) ToKeyBytes() []byte {
    return this.keyData
}

// 私钥/公钥
func (this DH) ToKeyString() string {
    return string(this.keyData)
}

// =================

// 输出字节
func (this DH) ToBytes() []byte {
    return this.secretData
}

// 输出字符
func (this DH) ToString() string {
    return string(this.secretData)
}

// 输出Base64
func (this DH) ToBase64String() string {
    return encoding.Base64Encode(this.secretData)
}

// 输出Hex
func (this DH) ToHexString() string {
    return encoding.HexEncode(this.secretData)
}
