package dsa

import (
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 私钥/公钥
func (this DSA) ToKeyBytes() []byte {
    return this.keyData
}

// 私钥/公钥
func (this DSA) ToKeyString() string {
    return string(this.keyData)
}

// ==========

// 输出字节
func (this DSA) ToBytes() []byte {
    return this.paredData
}

// 输出字符
func (this DSA) ToString() string {
    return string(this.paredData)
}

// 输出Base64
func (this DSA) ToBase64String() string {
    return cryptobin_tool.NewEncoding().Base64Encode(this.paredData)
}

// 输出Hex
func (this DSA) ToHexString() string {
    return cryptobin_tool.NewEncoding().HexEncode(this.paredData)
}

// ==========

// 验证结果
func (this DSA) ToVerify() bool {
    return this.verify
}

// 验证结果，返回 int 类型
func (this DSA) ToVerifyInt() int {
    if this.verify {
        return 1
    }

    return 0
}
