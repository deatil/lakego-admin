package crypto

import (
    "github.com/deatil/go-cryptobin/tool"
)

// 构造函数
func NewConfig(c Cryptobin) Config {
    return Config{
        crypto: c,
    }
}

/**
 * 包装配置
 *
 * @create 2023-3-30
 * @author deatil
 */
type Config struct {
    crypto Cryptobin
}

// 密钥
func (this Config) Key() []byte {
    return this.crypto.key
}

// 向量
func (this Config) Iv() []byte {
    return this.crypto.iv
}

// 加密类型
func (this Config) Multiple() Multiple {
    return this.crypto.multiple
}

// 加密模式
func (this Config) Mode() Mode {
    return this.crypto.mode
}

// 填充模式
func (this Config) Padding() Padding {
    return this.crypto.padding
}

// 额外配置
func (this Config) Config() *tool.Config {
    return this.crypto.config
}
