package ecdsa

import (
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 私钥/公钥
func (this Ecdsa) ToKeyBytes() []byte {
    return this.keyData
}

// 私钥/公钥
func (this Ecdsa) ToKeyString() string {
    return string(this.keyData)
}

// ==========

// 输出字节
func (this Ecdsa) ToBytes() []byte {
    return this.paredData
}

// 输出字符
func (this Ecdsa) ToString() string {
    return string(this.paredData)
}

// 输出Base64
func (this Ecdsa) ToBase64String() string {
    return cryptobin_tool.NewEncoding().Base64Encode(this.paredData)
}

// 输出Hex
func (this Ecdsa) ToHexString() string {
    return cryptobin_tool.NewEncoding().HexEncode(this.paredData)
}

// ==========

// 验证结果
func (this Ecdsa) ToVerify() bool {
    return this.verify
}

// 验证结果，返回 int 类型
func (this Ecdsa) ToVerifyInt() int {
    if this.verify {
        return 1
    }

    return 0
}
