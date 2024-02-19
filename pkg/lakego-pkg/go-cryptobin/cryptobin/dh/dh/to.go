package dh

import (
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
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
    return cryptobin_tool.NewEncoding().Base64Encode(this.secretData)
}

// 输出Hex
func (this DH) ToHexString() string {
    return cryptobin_tool.NewEncoding().HexEncode(this.secretData)
}
