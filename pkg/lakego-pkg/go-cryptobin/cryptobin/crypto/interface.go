package crypto

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool"
)

// 配置接口
type IOption interface {
    // 密钥
    Key() []byte

    // 向量
    Iv() []byte

    // 加密类型
    Multiple() Multiple

    // 加密模式
    Mode() Mode

    // 填充模式
    Padding() Padding

    // 额外配置
    Config() *tool.Config
}

// 加密接口
type IEncrypt interface {
    // 加密
    Encrypt([]byte, IOption) ([]byte, error)

    // 解密
    Decrypt([]byte, IOption) ([]byte, error)
}

// 模式接口
type IMode interface {
    // 加密
    Encrypt([]byte, cipher.Block, IOption) ([]byte, error)

    // 解密
    Decrypt([]byte, cipher.Block, IOption) ([]byte, error)
}

// 填充接口
type IPadding interface {
    // 补码
    Padding([]byte, int, IOption) []byte

    // 解密
    UnPadding([]byte, IOption) ([]byte, error)
}
