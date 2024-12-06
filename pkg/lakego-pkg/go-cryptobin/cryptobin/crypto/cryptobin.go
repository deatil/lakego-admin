package crypto

import (
    "github.com/deatil/go-cryptobin/tool/config"
    "github.com/deatil/go-cryptobin/tool/error_event"
)

/**
 * 对称加密 / Cryptobin
 *
 * @create 2022-3-19
 * @author deatil
 */
type Cryptobin struct {
    // 数据 / data
    data []byte

    // 密钥 / key
    key []byte

    // 向量 / iv
    iv []byte

    // 加密类型 / multiple
    multiple Multiple

    // 加密模式 / crypto mode
    mode Mode

    // 填充模式 / padding type
    padding Padding

    // 额外配置 / extra Config
    config *config.Config

    // 解析后的数据 / parsed Data
    parsedData []byte

    // 事件 / error Event
    errEvent error_event.ErrorEvent

    // 错误 / error list
    Errors []error
}

// New Cryptobin
func NewCryptobin() Cryptobin {
    return Cryptobin{
        multiple: Aes,
        mode:     ECB,
        padding:  NoPadding,
        config:   config.New(),
        errEvent: error_event.New(),
        Errors:   make([]error, 0),
    }
}

// 构造函数
// New Cryptobin
func New() Cryptobin {
    return NewCryptobin()
}

var (
    // 默认
    // default new Cryptobin
    defaultCryptobin = NewCryptobin()
)
