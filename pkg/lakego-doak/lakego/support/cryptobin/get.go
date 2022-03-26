package cryptobin

// 数据
func (this Crypto) GetData() []byte {
    return this.Data
}

// 密码
func (this Crypto) GetKey() []byte {
    return this.Key
}

// 向量
func (this Crypto) GetIv() []byte {
    return this.Iv
}

// 加密类型
func (this Crypto) GetType() string {
    return this.Type
}

// 加密方式
func (this Crypto) GetMode() string {
    return this.Mode
}

// 补码算法
func (this Crypto) GetPadding() string {
    return this.Padding
}

// 解析后的数据
func (this Crypto) GetParsedData() []byte {
    return this.ParsedData
}

// 错误信息
func (this Crypto) GetError() error {
    return this.Error
}
