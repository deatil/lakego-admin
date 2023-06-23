package elgamal

import (
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
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
    return this.paredData
}

// 输出字符
func (this EIGamal) ToString() string {
    return string(this.paredData)
}

// 输出Base64
func (this EIGamal) ToBase64String() string {
    return cryptobin_tool.NewEncoding().Base64Encode(this.paredData)
}

// 输出Hex
func (this EIGamal) ToHexString() string {
    return cryptobin_tool.NewEncoding().HexEncode(this.paredData)
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
