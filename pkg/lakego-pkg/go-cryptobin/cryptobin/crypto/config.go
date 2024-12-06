package crypto

import (
    "github.com/deatil/go-cryptobin/tool/config"
)

/**
 * 配置 / Config
 *
 * @create 2023-3-30
 * @author deatil
 */
type Config struct {
    crypto Cryptobin
}

// New Config
func NewConfig(c Cryptobin) Config {
    return Config{
        crypto: c,
    }
}

// 获取密钥
// get Key
func (this Config) Key() []byte {
    return this.crypto.key
}

// 获取向量
// get Iv
func (this Config) Iv() []byte {
    return this.crypto.iv
}

// 获取加密类型
// get Multiple
func (this Config) Multiple() Multiple {
    return this.crypto.multiple
}

// 获取加密模式
// get Mode
func (this Config) Mode() Mode {
    return this.crypto.mode
}

// 获取补码
// get Padding
func (this Config) Padding() Padding {
    return this.crypto.padding
}

// 获取额外配置
// get extra Config
func (this Config) Config() *config.Config {
    return this.crypto.config
}
