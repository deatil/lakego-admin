package rsa

import (
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 私钥/公钥
func (this Rsa) ToKeyBytes() []byte {
    return this.keyData
}

// 私钥/公钥
func (this Rsa) ToKeyString() string {
    return string(this.keyData)
}

// ==========

// 输出字节
func (this Rsa) ToBytes() []byte {
    return this.parsedData
}

// 输出字符
func (this Rsa) ToString() string {
    return string(this.parsedData)
}

// 输出Base64
func (this Rsa) ToBase64String() string {
    return cryptobin_tool.NewEncoding().Base64Encode(this.parsedData)
}

// 输出Hex
func (this Rsa) ToHexString() string {
    return cryptobin_tool.NewEncoding().HexEncode(this.parsedData)
}

// ==========

// 验证结果
func (this Rsa) ToVerify() bool {
    return this.verify
}

// 验证结果，返回 int 类型
func (this Rsa) ToVerifyInt() int {
    if this.verify {
        return 1
    }

    return 0
}
