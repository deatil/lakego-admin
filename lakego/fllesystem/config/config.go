package config

import(
    "lakego-admin/lakego/fllesystem/interfaces"
)

/**
 * 配置
 *
 * @create 2021-8-1
 * @author deatil
 */
type Config struct {
    settings map[string]interface{}

    fallback interfaces.Config
}

/**
 * 初始化
 */
func New(settings map[string]interface{}) *Config {
    conf := &Config{}

    conf.WithSetting(settings)

    return conf
}

/**
 * 设置配置信息
 */
func (conf *Config) WithSetting(settings map[string]interface{}) interfaces.Config {
    conf.settings = settings

    return conf
}

/**
 * 设置配置信息
 */
func (conf *Config) With(key string, value interface{}) interfaces.Config {
    conf.settings[key] = value

    return conf
}

/**
 * 获取一个设置
 */
func (conf *Config) Get(key string) interface{} {
    if data, ok := conf.settings[key]; ok {
        return data
    }

    if conf.fallback != nil {
        return conf.fallback.Get(key)
    }

    return nil
}

/**
 * 通过一个 key 值判断设置是否存在
 */
func (conf *Config) Has(key string) bool {
    if _, ok := conf.settings[key]; ok {
        return true
    }

    if conf.fallback != nil {
        return conf.fallback.Has(key)
    }

    return false
}

/**
 * 获取一个值带默认
 */
func (conf *Config) GetDefault(key string, defaults ...interface{}) interface{} {
    if data, ok := conf.settings[key]; ok {
        return data
    }

    if conf.fallback != nil {
        return conf.fallback.GetDefault(key, defaults...)
    }

    if len(defaults) > 0 {
        return defaults[0]
    }

    return nil
}

/**
 * 设置
 */
func (conf *Config) Set(key string, value interface{}) interfaces.Config {
    conf.settings[key] = value

    return conf
}

/**
 * 设置一个 fallback
 */
func (conf *Config) SetFallback(fallback interfaces.Config) interfaces.Config {
    conf.fallback = fallback

    return conf
}

