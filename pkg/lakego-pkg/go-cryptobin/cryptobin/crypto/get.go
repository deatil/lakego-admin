package crypto

import (
    "github.com/deatil/go-cryptobin/tool/config"
)

// 获取数据
// Get Data
func (this Cryptobin) GetData() []byte {
    return this.data
}

// 获取密码
// Get Key
func (this Cryptobin) GetKey() []byte {
    return this.key
}

// 获取向量
// Get Iv
func (this Cryptobin) GetIv() []byte {
    return this.iv
}

// 获取加密类型
// Get Multiple type
func (this Cryptobin) GetMultiple() Multiple {
    return this.multiple
}

// 获取加密方式
// Get Mode type
func (this Cryptobin) GetMode() Mode {
    return this.mode
}

// 获取补码算法
// Get Padding
func (this Cryptobin) GetPadding() Padding {
    return this.padding
}

// 获取解析后的数据
// Get ParsedData
func (this Cryptobin) GetParsedData() []byte {
    return this.parsedData
}

// 获取获取全部配置
// Get Config
func (this Cryptobin) GetConfig() *config.Config {
    return this.config
}

// 获取获取一个配置
// Get One Config
func (this Cryptobin) GetOneConfig(key string) any {
    return this.config.Get(key)
}

// 获取错误信息
// Get Error list
func (this Cryptobin) GetErrors() []error {
    return this.Errors
}
