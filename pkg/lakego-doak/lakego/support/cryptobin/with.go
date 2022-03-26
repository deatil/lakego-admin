package cryptobin

// 设置数据
func (this Crypto) WithData(data []byte) Crypto {
    this.Data = data

    return this
}

// 设置密钥
func (this Crypto) WithKey(data []byte) Crypto {
    this.Key = data

    return this
}

// 设置向量
func (this Crypto) WithIv(data []byte) Crypto {
    this.Iv = data

    return this
}

// 加密类型
func (this Crypto) WithType(data string) Crypto {
    this.Type = data

    return this
}

// 加密方式
func (this Crypto) WithMode(data string) Crypto {
    this.Mode = data

    return this
}

// 补码算法
func (this Crypto) WithPadding(data string) Crypto {
    this.Padding = data

    return this
}
