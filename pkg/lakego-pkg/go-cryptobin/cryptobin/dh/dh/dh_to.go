package dh

import (
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 私钥/公钥
func (this Dh) ToKeyBytes() []byte {
    return this.keyData
}

// 私钥/公钥
func (this Dh) ToKeyString() string {
    return string(this.keyData)
}

// =================

// 输出字节
func (this Dh) ToBytes() []byte {
    return this.secretData
}

// 输出字符
func (this Dh) ToString() string {
    return string(this.secretData)
}

// 输出Base64
func (this Dh) ToBase64String() string {
    return cryptobin_tool.NewEncoding().Base64Encode(this.secretData)
}

// 输出Hex
func (this Dh) ToHexString() string {
    return cryptobin_tool.NewEncoding().HexEncode(this.secretData)
}
