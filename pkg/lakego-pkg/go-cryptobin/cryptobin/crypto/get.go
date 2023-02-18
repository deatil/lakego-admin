package crypto

import (
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

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
func (this Cryptobin) GetMultiple() Multiple {
    return this.multiple
}

// 加密方式
func (this Cryptobin) GetMode() Mode {
    return this.mode
}

// 补码算法
func (this Cryptobin) GetPadding() Padding {
    return this.padding
}

// 解析后的数据
func (this Cryptobin) GetParsedData() []byte {
    return this.parsedData
}

// 获取全部配置
func (this Cryptobin) GetConfig() *cryptobin_tool.Config {
    return this.config
}

// 获取一个配置
func (this Cryptobin) GetOneConfig(key string) any {
    return this.config.Get(key)
}

// 错误信息
func (this Cryptobin) GetErrors() []error {
    return this.Errors
}

// 获取错误
func (this Cryptobin) Error() *cryptobin_tool.Errors {
    return cryptobin_tool.NewError(this.Errors...)
}
