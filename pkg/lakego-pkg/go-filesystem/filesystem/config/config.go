package config

import(
    "github.com/deatil/go-filesystem/filesystem/interfaces"
)

/**
 * 配置
 *
 * @create 2021-8-1
 * @author deatil
 */
type Config struct {
    // 数据
    data map[string]any
}

/**
 * 构造函数
 */
func New(data map[string]any) Config {
    return Config{
        data: data,
    }
}

/**
 * 覆盖旧数据
 */
func (this Config) With(data map[string]any) interfaces.Config {
    this.data = data

    return this
}

/**
 * 设置单个新数据
 */
func (this Config) Set(key string, value any) interfaces.Config {
    this.data[key] = value

    return this
}

/**
 * 是否存在
 */
func (this Config) Has(key string) bool {
    if _, ok := this.data[key]; ok {
        return true
    }

    return false
}

/**
 * 获取一个带默认的值
 */
func (this Config) Get(key string, defaults ...any) any {
    if data, ok := this.data[key]; ok {
        return data
    }

    if len(defaults) > 0 {
        return defaults[0]
    }

    return nil
}
