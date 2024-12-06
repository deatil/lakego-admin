package gost

import (
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// 私钥/公钥
func (this Gost) ToKeyBytes() []byte {
    return this.keyData
}

// 私钥/公钥
func (this Gost) ToKeyString() string {
    return string(this.keyData)
}

// ==========

// 输出字节
func (this Gost) ToBytes() []byte {
    return this.parsedData
}

// 输出字符
func (this Gost) ToString() string {
    return string(this.parsedData)
}

// 输出Base64
func (this Gost) ToBase64String() string {
    return encoding.Base64Encode(this.parsedData)
}

// 输出Hex
func (this Gost) ToHexString() string {
    return encoding.HexEncode(this.parsedData)
}

// ==========

// 验证结果
func (this Gost) ToVerify() bool {
    return this.verify
}

// 验证结果，返回 int 类型
func (this Gost) ToVerifyInt() int {
    if this.verify {
        return 1
    }

    return 0
}

// =================

// 输出密钥字节
func (this Gost) ToSecretBytes() []byte {
    return this.secretData
}

// 输出密钥字符
func (this Gost) ToSecretString() string {
    return string(this.secretData)
}

// 输出密钥 Base64
func (this Gost) ToSecretBase64String() string {
    return encoding.Base64Encode(this.secretData)
}

// 输出密钥 Hex
func (this Gost) ToSecretHexString() string {
    return encoding.HexEncode(this.secretData)
}
