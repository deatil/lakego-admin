package config

import(
    "github.com/deatil/go-filesystem/filesystem/interfaces"
)

/**
 * 初始化
 */
func New(settings map[string]interface{}) *Config {
    conf := &Config{}

    conf.WithSetting(settings)

    return conf
}

/**
 * 配置
 *
 * @create 2021-8-1
 * @author deatil
 */
type Config struct {
    // 设置
    settings map[string]interface{}

    // 配置
    fallback interfaces.Config
}

/**
 * 设置配置信息
 */
func (this *Config) WithSetting(settings map[string]interface{}) interfaces.Config {
    this.settings = settings

    return this
}

/**
 * 设置配置信息
 */
func (this *Config) With(key string, value interface{}) interfaces.Config {
    this.settings[key] = value

    return this
}

/**
 * 获取一个设置
 */
func (this *Config) Get(key string) interface{} {
    if data, ok := this.settings[key]; ok {
        return data
    }

    if this.fallback != nil {
        return this.fallback.Get(key)
    }

    return nil
}

/**
 * 通过一个 key 值判断设置是否存在
 */
func (this *Config) Has(key string) bool {
    if _, ok := this.settings[key]; ok {
        return true
    }

    if this.fallback != nil {
        return this.fallback.Has(key)
    }

    return false
}

/**
 * 获取一个值带默认
 */
func (this *Config) GetDefault(key string, defaults ...interface{}) interface{} {
    if data, ok := this.settings[key]; ok {
        return data
    }

    if this.fallback != nil {
        return this.fallback.GetDefault(key, defaults...)
    }

    if len(defaults) > 0 {
        return defaults[0]
    }

    return nil
}

/**
 * 设置
 */
func (this *Config) Set(key string, value interface{}) interfaces.Config {
    this.settings[key] = value

    return this
}

/**
 * 设置一个 fallback
 */
func (this *Config) SetFallback(fallback interfaces.Config) interfaces.Config {
    this.fallback = fallback

    return this
}

