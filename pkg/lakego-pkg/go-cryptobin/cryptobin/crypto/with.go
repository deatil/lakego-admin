package crypto

import (
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 设置数据
func (this Cryptobin) WithData(data []byte) Cryptobin {
    this.data = data

    return this
}

// 设置密钥
func (this Cryptobin) WithKey(key []byte) Cryptobin {
    this.key = key

    return this
}

// 设置向量
func (this Cryptobin) WithIv(iv []byte) Cryptobin {
    this.iv = iv

    return this
}

// 加密类型
func (this Cryptobin) WithMultiple(multiple Multiple) Cryptobin {
    this.multiple = multiple

    return this
}

// 加密方式
func (this Cryptobin) WithMode(mode Mode) Cryptobin {
    this.mode = mode

    return this
}

// 补码算法
func (this Cryptobin) WithPadding(padding Padding) Cryptobin {
    this.padding = padding

    return this
}

// 补码算法
func (this Cryptobin) WithParsedData(data []byte) Cryptobin {
    this.parsedData = data

    return this
}

// 配置
func (this Cryptobin) WithConfig(config *cryptobin_tool.Config) Cryptobin {
    this.config = config

    return this
}

// 设置配置
func (this Cryptobin) SetConfig(data map[string]any) Cryptobin {
    this.config.WithData(data)

    return this
}

// 设置一个配置
func (this Cryptobin) WithOneConfig(key string, value any) Cryptobin {
    this.config.Set(key, value)

    return this
}

// 设置错误
func (this Cryptobin) WithErrors(errs []error) Cryptobin {
    this.Errors = errs

    return this
}

// 添加错误
func (this Cryptobin) AppendError(err ...error) Cryptobin {
    this.Errors = append(this.Errors, err...)

    return this
}
