package crypto

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/config"
)

// 配置接口
// config interface
type IOption interface {
    // 密钥
    // get Key
    Key() []byte

    // 向量
    // get Iv
    Iv() []byte

    // 加密类型
    // get Multiple
    Multiple() Multiple

    // 加密模式
    // get Mode
    Mode() Mode

    // 填充模式
    // get Padding
    Padding() Padding

    // 额外配置
    // get extra Config
    Config() *config.Config
}

// 加密接口
// Encrypt interface
type IEncrypt interface {
    // 加密
    // Encrypt
    Encrypt([]byte, IOption) ([]byte, error)

    // 解密
    // Decrypt
    Decrypt([]byte, IOption) ([]byte, error)
}

// 模式接口
// Mode interface
type IMode interface {
    // 加密
    // Encrypt
    Encrypt([]byte, cipher.Block, IOption) ([]byte, error)

    // 解密
    // Decrypt
    Decrypt([]byte, cipher.Block, IOption) ([]byte, error)
}

// 填充接口
// Padding interface
type IPadding interface {
    // 补码
    // Padding
    Padding([]byte, int, IOption) []byte

    // 解密
    // UnPadding
    UnPadding([]byte, IOption) ([]byte, error)
}
