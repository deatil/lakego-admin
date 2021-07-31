package config

type Config struct {
    settings map[string]interface{}

    fallback *Config
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
func (conf *Config) WithSetting(settings map[string]interface{}) *Config {
    conf.settings = settings

    return conf
}

/**
 * 设置配置信息
 */
func (conf *Config) With(key string, value interface{}) *Config {
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

    return nil
}

/**
 * 通过一个 key 值判断设置是否存在
 */
func (conf *Config) Has(key string) bool {
    if _, ok := conf.settings[key]; ok {
        return true
    }

    return conf.fallback.Has(key)
}

/**
 * 获取一个值带默认
 */
func (conf *Config) GetDefault(key string, defaults ...interface{}) interface{} {
    if conf.fallback == nil {
        return false
    }

    value := conf.fallback.Get(key)
    if value == nil && len(defaults) > 0 {
        return defaults[0]
    }

    return value
}

/**
 * 设置
 */
func (conf *Config) Set(key string, value interface{}) *Config {
    conf.settings[key] = value

    return conf
}

/**
 * 设置一个 fallback
 */
func (conf *Config) SetFallback(fallback *Config) *Config {
    conf.fallback = fallback

    return conf
}

