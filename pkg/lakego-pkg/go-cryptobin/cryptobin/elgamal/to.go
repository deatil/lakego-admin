package elgamal

import (
    "github.com/deatil/go-cryptobin/tool"
)

// 私钥/公钥
func (this EIGamal) ToKeyBytes() []byte {
    return this.keyData
}

// 私钥/公钥
func (this EIGamal) ToKeyString() string {
    return string(this.keyData)
}

// ==========

// 输出字节
func (this EIGamal) ToBytes() []byte {
    return this.parsedData
}

// 输出字符
func (this EIGamal) ToString() string {
    return string(this.parsedData)
}

// 输出Base64
func (this EIGamal) ToBase64String() string {
    return tool.Base64Encode(this.parsedData)
}

// 输出Hex
func (this EIGamal) ToHexString() string {
    return tool.HexEncode(this.parsedData)
}

// ==========

// 验证结果
func (this EIGamal) ToVerify() bool {
    return this.verify
}

// 验证结果，返回 int 类型
func (this EIGamal) ToVerifyInt() int {
    if this.verify {
        return 1
    }

    return 0
}
