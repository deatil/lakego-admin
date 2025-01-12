package ecsdsa

import (
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// 私钥/公钥
func (this ECSDSA) ToKeyBytes() []byte {
    return this.keyData
}

// 私钥/公钥
func (this ECSDSA) ToKeyString() string {
    return string(this.keyData)
}

// ==========

// 输出字节
func (this ECSDSA) ToBytes() []byte {
    return this.parsedData
}

// 输出字符
func (this ECSDSA) ToString() string {
    return string(this.parsedData)
}

// 输出Base64
func (this ECSDSA) ToBase64String() string {
    return encoding.Base64Encode(this.parsedData)
}

// 输出Hex
func (this ECSDSA) ToHexString() string {
    return encoding.HexEncode(this.parsedData)
}

// ==========

// 验证结果
func (this ECSDSA) ToVerify() bool {
    return this.verify
}

// 验证结果，返回 int 类型
func (this ECSDSA) ToVerifyInt() int {
    if this.verify {
        return 1
    }

    return 0
}
