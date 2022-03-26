package cryptobin

// 设置数据
func (this Cryptobin) WithData(data []byte) Cryptobin {
    this.data = data

    return this
}

// 设置密钥
func (this Cryptobin) WithKey(data []byte) Cryptobin {
    this.key = data

    return this
}

// 设置向量
func (this Cryptobin) WithIv(data []byte) Cryptobin {
    this.iv = data

    return this
}

// 加密类型
func (this Cryptobin) WithType(data string) Cryptobin {
    this.multiple = data

    return this
}

// 加密方式
func (this Cryptobin) WithMode(data string) Cryptobin {
    this.mode = data

    return this
}

// 补码算法
func (this Cryptobin) WithPadding(data string) Cryptobin {
    this.padding = data

    return this
}
