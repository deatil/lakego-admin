package crypto

import (
    "github.com/deatil/go-cryptobin/tool"
)

// 设置数据
func (this Cryptobin) WithData(data []byte) Cryptobin {
    this.data = data

    return this
}

// 设置数据
func (this Cryptobin) SetData(data string) Cryptobin {
    this.data = []byte(data)

    return this
}

// 设置密钥
func (this Cryptobin) WithKey(key []byte) Cryptobin {
    this.key = key

    return this
}

// 密码
func (this Cryptobin) SetKey(data string) Cryptobin {
    this.key = []byte(data)

    return this
}

// 设置向量
func (this Cryptobin) WithIv(iv []byte) Cryptobin {
    this.iv = iv

    return this
}

// 向量
func (this Cryptobin) SetIv(data string) Cryptobin {
    this.iv = []byte(data)

    return this
}

// 加密类型
func (this Cryptobin) WithMultiple(multiple Multiple) Cryptobin {
    this.multiple = multiple

    return this
}

// 设置加密类型带参数
func (this Cryptobin) SetMultiple(multiple Multiple, cfg map[string]any) Cryptobin {
    this.multiple = multiple

    if len(cfg) > 0 {
        for k, v := range cfg {
            this.config.Set(k, v)
        }
    }

    return this
}

// 加密方式
func (this Cryptobin) WithMode(mode Mode) Cryptobin {
    this.mode = mode

    return this
}

// 设置加密模式带参数
func (this Cryptobin) SetMode(mode Mode, cfg map[string]any) Cryptobin {
    this.mode = mode

    if len(cfg) > 0 {
        for k, v := range cfg {
            this.config.Set(k, v)
        }
    }

    return this
}

// 补码算法
func (this Cryptobin) WithPadding(padding Padding) Cryptobin {
    this.padding = padding

    return this
}

// 设置补码算法带参数
func (this Cryptobin) SetPadding(padding Padding, cfg map[string]any) Cryptobin {
    this.padding = padding

    if len(cfg) > 0 {
        for k, v := range cfg {
            this.config.Set(k, v)
        }
    }

    return this
}

// 设置配置
func (this Cryptobin) WithConfig(config *tool.Config) Cryptobin {
    this.config = config

    return this
}

// 批量设置配置
func (this Cryptobin) SetConfig(data map[string]any) Cryptobin {
    this.config.WithData(data)

    return this
}

// 设置一个配置
func (this Cryptobin) PutConfig(key string, value any) Cryptobin {
    this.config.Set(key, value)

    return this
}

// 设置解析后的数据
func (this Cryptobin) WithParsedData(data []byte) Cryptobin {
    this.parsedData = data

    return this
}

// 设置解析后的数据
func (this Cryptobin) SetParsedData(data string) Cryptobin {
    this.parsedData = []byte(data)

    return this
}

// 设置错误
func (this Cryptobin) WithErrors(errs []error) Cryptobin {
    this.Errors = errs

    return this
}
