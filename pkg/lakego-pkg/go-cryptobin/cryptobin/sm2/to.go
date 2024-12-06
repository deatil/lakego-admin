package sm2

import (
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// 私钥/公钥
func (this SM2) ToKeyBytes() []byte {
    return this.keyData
}

// 私钥/公钥
func (this SM2) ToKeyString() string {
    return string(this.keyData)
}

// ==========

// 输出字节
func (this SM2) ToBytes() []byte {
    return this.parsedData
}

// 输出字符
func (this SM2) ToString() string {
    return string(this.parsedData)
}

// 输出Base64
func (this SM2) ToBase64String() string {
    return encoding.Base64Encode(this.parsedData)
}

// 输出Hex
func (this SM2) ToHexString() string {
    return encoding.HexEncode(this.parsedData)
}

// ==========

// 验证结果
func (this SM2) ToVerify() bool {
    return this.verify
}

// 验证结果，返回 int 类型
func (this SM2) ToVerifyInt() int {
    if this.verify {
        return 1
    }

    return 0
}
