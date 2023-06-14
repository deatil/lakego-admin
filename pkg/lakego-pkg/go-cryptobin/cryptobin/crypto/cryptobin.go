package crypto

import (
    "github.com/deatil/go-cryptobin/tool"
)

/**
 * 对称加密
 *
 * @create 2022-3-19
 * @author deatil
 */
type Cryptobin struct {
    // 数据
    data []byte

    // 密钥
    key []byte

    // 向量
    iv []byte

    // 加密类型
    multiple Multiple

    // 加密模式
    mode Mode

    // 填充模式
    padding Padding

    // 额外配置
    config *tool.Config

    // 解析后的数据
    parsedData []byte

    // 错误
    Errors []error
}

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

var (
    // 默认
    defaultCryptobin = NewCryptobin()
)
