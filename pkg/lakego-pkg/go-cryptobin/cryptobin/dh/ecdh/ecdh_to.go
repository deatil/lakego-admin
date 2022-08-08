package ecdh

import (
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 私钥/公钥
func (this Ecdh) ToKeyBytes() []byte {
    return this.keyData
}

// 私钥/公钥
func (this Ecdh) ToKeyString() string {
    return string(this.keyData)
}

// =================

// 输出字节
func (this Ecdh) ToBytes() []byte {
    return this.secretData
}

// 输出字符
func (this Ecdh) ToString() string {
    return string(this.secretData)
}

// 输出Base64
func (this Ecdh) ToBase64String() string {
    return cryptobin_tool.NewEncoding().Base64Encode(this.secretData)
}

// 输出Hex
func (this Ecdh) ToHexString() string {
    return cryptobin_tool.NewEncoding().HexEncode(this.secretData)
}
