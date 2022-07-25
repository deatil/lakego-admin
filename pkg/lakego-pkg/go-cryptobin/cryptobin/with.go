package cryptobin

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
func (this Cryptobin) WithMultiple(multiple string) Cryptobin {
    this.multiple = multiple

    return this
}

// 加密方式
func (this Cryptobin) WithMode(mode string) Cryptobin {
    this.mode = mode

    return this
}

// 补码算法
func (this Cryptobin) WithPadding(padding string) Cryptobin {
    this.padding = padding

    return this
}

// 补码算法
func (this Cryptobin) WithParsedData(data []byte) Cryptobin {
    this.parsedData = data

    return this
}

// 配置
func (this Cryptobin) WithConfig(config map[string]any) Cryptobin {
    this.config = config

    return this
}

// 设置一个配置
func (this Cryptobin) WithOneConfig(key string, value any) Cryptobin {
    this.config[key] = value

    return this
}

// 设置错误
func (this Cryptobin) WithError(err error) Cryptobin {
    this.Error = err

    return this
}
