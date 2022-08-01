package config

import(
    "github.com/deatil/go-filesystem/filesystem/interfaces"
)

/**
 * 构造函数
 */
func New(data DataMap) Config {
    return Config{
        Data: data,
    }
}

type (
    // 配置 map
    DataMap = map[string]any
)

/**
 * 配置
 *
 * @create 2021-8-1
 * @author deatil
 */
type Config struct {
    // 数据
    Data DataMap
}

/**
 * 覆盖旧数据
 */
func (this Config) With(data DataMap) interfaces.Config {
    this.Data = data

    return this
}

/**
 * 设置单个新数据
 */
func (this Config) Set(key string, value any) interfaces.Config {
    this.Data[key] = value

    return this
}

/**
 * 是否存在
 */
func (this Config) Has(key string) bool {
    if _, ok := this.Data[key]; ok {
        return true
    }

    return false
}

/**
 * 获取一个带默认的值
 */
func (this Config) Get(key string, defaults ...any) any {
    if data, ok := this.Data[key]; ok {
        return data
    }

    if len(defaults) > 0 {
        return defaults[0]
    }

    return nil
}
