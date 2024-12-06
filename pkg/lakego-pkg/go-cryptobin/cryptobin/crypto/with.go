package crypto

import (
    "github.com/deatil/go-cryptobin/tool/config"
)

// 设置数据
// set Data bytes
func (this Cryptobin) WithData(data []byte) Cryptobin {
    this.data = data

    return this
}

// 设置数据
// set Data string
func (this Cryptobin) SetData(data string) Cryptobin {
    this.data = []byte(data)

    return this
}

// 设置密钥
// set Key bytes
func (this Cryptobin) WithKey(key []byte) Cryptobin {
    this.key = key

    return this
}

// 密码
// set Key string
func (this Cryptobin) SetKey(data string) Cryptobin {
    this.key = []byte(data)

    return this
}

// 设置向量
// set Key bytes
func (this Cryptobin) WithIv(iv []byte) Cryptobin {
    this.iv = iv

    return this
}

// 设置向量
// set Key string
func (this Cryptobin) SetIv(data string) Cryptobin {
    this.iv = []byte(data)

    return this
}

// 设置加密类型
// set Encrypt multiple
func (this Cryptobin) WithMultiple(multiple Multiple) Cryptobin {
    this.multiple = multiple

    return this
}

// 设置加密类型带参数
// set Encrypt multiple with config
func (this Cryptobin) SetMultiple(multiple Multiple, cfg map[string]any) Cryptobin {
    this.multiple = multiple

    if len(cfg) > 0 {
        for k, v := range cfg {
            this.config.Set(k, v)
        }
    }

    return this
}

// 设置加密方式
// set mode type
func (this Cryptobin) WithMode(mode Mode) Cryptobin {
    this.mode = mode

    return this
}

// 设置加密模式带参数
// set mode type with config
func (this Cryptobin) SetMode(mode Mode, cfg map[string]any) Cryptobin {
    this.mode = mode

    if len(cfg) > 0 {
        for k, v := range cfg {
            this.config.Set(k, v)
        }
    }

    return this
}

// 设置补码方式
// set padding type
func (this Cryptobin) WithPadding(padding Padding) Cryptobin {
    this.padding = padding

    return this
}

// 设置补码方式带参数
// set padding type with config
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
// set config
func (this Cryptobin) WithConfig(config *config.Config) Cryptobin {
    this.config = config

    return this
}

// 批量设置配置
// set config map
func (this Cryptobin) SetConfig(data map[string]any) Cryptobin {
    this.config.WithData(data)

    return this
}

// 设置一个配置
// set one config
func (this Cryptobin) PutConfig(key string, value any) Cryptobin {
    this.config.Set(key, value)

    return this
}

// 设置解析后的数据
// set parsedData bytes
func (this Cryptobin) WithParsedData(data []byte) Cryptobin {
    this.parsedData = data

    return this
}

// 设置解析后的数据
// set parsedData string
func (this Cryptobin) SetParsedData(data string) Cryptobin {
    this.parsedData = []byte(data)

    return this
}

// 设置错误
// set error list
func (this Cryptobin) WithErrors(errs []error) Cryptobin {
    this.Errors = errs

    return this
}
