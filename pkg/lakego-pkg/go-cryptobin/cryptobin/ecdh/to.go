package ecdh

import (
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 私钥/公钥
func (this ECDH) ToKeyBytes() []byte {
    return this.keyData
}

// 私钥/公钥
func (this ECDH) ToKeyString() string {
    return string(this.keyData)
}

// =================

// 输出字节
func (this ECDH) ToBytes() []byte {
    return this.secretData
}

// 输出字符
func (this ECDH) ToString() string {
    return string(this.secretData)
}

// 输出Base64
func (this ECDH) ToBase64String() string {
    return cryptobin_tool.NewEncoding().Base64Encode(this.secretData)
}

// 输出Hex
func (this ECDH) ToHexString() string {
    return cryptobin_tool.NewEncoding().HexEncode(this.secretData)
}
