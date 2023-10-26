package ed448

import (
    "github.com/deatil/go-cryptobin/tool"
)

// 私钥/公钥
func (this ED448) ToKeyBytes() []byte {
    return this.keyData
}

// 私钥/公钥
func (this ED448) ToKeyString() string {
    return string(this.keyData)
}

// ==========

// 输出字节
func (this ED448) ToBytes() []byte {
    return this.paredData
}

// 输出字符
func (this ED448) ToString() string {
    return string(this.paredData)
}

// 输出Base64
func (this ED448) ToBase64String() string {
    return tool.Base64Encode(this.paredData)
}

// 输出Hex
func (this ED448) ToHexString() string {
    return tool.HexEncode(this.paredData)
}

// ==========

// 验证结果
func (this ED448) ToVerify() bool {
    return this.verify
}

// 验证结果，返回 int 类型
func (this ED448) ToVerifyInt() int {
    if this.verify {
        return 1
    }

    return 0
}
