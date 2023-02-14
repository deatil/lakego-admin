package crypto

import (
    "github.com/deatil/go-cryptobin/tool"
)

// 构造函数
func NewCryptobin() Cryptobin {
    return Cryptobin{
        multiple: Aes,
        mode:     ECB,
        padding:  NoPadding,
        config:   tool.NewConfig(),
        Errors:   make([]error, 0),
    }
}

// 构造函数
func New() Cryptobin {
    return NewCryptobin()
}

// ==========

// 字节
func FromBytes(data []byte) Cryptobin {
    return NewCryptobin().FromBytes(data)
}

// 字符
func FromString(data string) Cryptobin {
    return NewCryptobin().FromString(data)
}

// Base64
func FromBase64String(data string) Cryptobin {
    return NewCryptobin().FromBase64String(data)
}

// Hex
func FromHexString(data string) Cryptobin {
    return NewCryptobin().FromHexString(data)
}
