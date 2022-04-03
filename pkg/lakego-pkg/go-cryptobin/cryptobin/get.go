package cryptobin

// 数据
func (this Cryptobin) GetData() []byte {
    return this.data
}

// 密码
func (this Cryptobin) GetKey() []byte {
    return this.key
}

// 向量
func (this Cryptobin) GetIv() []byte {
    return this.iv
}

// 加密类型
func (this Cryptobin) GetType() string {
    return this.multiple
}

// 加密方式
func (this Cryptobin) GetMode() string {
    return this.mode
}

// 补码算法
func (this Cryptobin) GetPadding() string {
    return this.padding
}

// 解析后的数据
func (this Cryptobin) GetParsedData() []byte {
    return this.parsedData
}

// 获取配置
func (this Cryptobin) GetConfig(key string) []byte {
    if data, ok := this.config[key]; ok {
        return data
    }

    return nil
}

// 获取全部配置
func (this Cryptobin) GetConfigs() map[string][]byte {
    return this.config
}

// 错误信息
func (this Cryptobin) GetError() error {
    return this.Error
}
