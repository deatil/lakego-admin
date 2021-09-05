package config

import (
    "log"
    "time"

    "github.com/fsnotify/fsnotify"
    "github.com/spf13/viper"

    "lakego-admin/lakego/support/path"
    "lakego-admin/lakego/config/interfaces"
)

/**
 * 配置
 *
 * @create 2021-6-19
 * @author deatil
 */
type Config struct {
    adapter *viper.Viper
}

// 参数设置为可变参数的文件名
func New(fileName ...string) interfaces.Config {
    conf := viper.New()

    // 配置文件夹
    configPath := path.FormatPath("{root}/config")

    // 配置文件所在目录
    conf.AddConfigPath(configPath)

    // 需要读取的文件名,默认为：config
    if len(fileName) == 0 {
        conf.SetConfigName("admin")
    } else {
        conf.SetConfigName(fileName[0])
    }

    // 设置配置文件类型(后缀)为 yml
    if len(fileName) <= 1 {
        conf.SetConfigType("yml")
    } else {
        conf.SetConfigType(fileName[1])
    }

    if err := conf.ReadInConfig(); err != nil {
        log.Fatal(err.Error())
    }

    // 设置根目录
    conf.AddConfigPath(".")
    conf.ReadInConfig()

    // 配置里读取
    _ = conf.ReadInConfig()

    // 环境变量
    conf.AutomaticEnv()
    conf.AllowEmptyEnv(true)

    // 事件
    conf.OnConfigChange(func(changeEvent fsnotify.Event) {
        if changeEvent.Op.String() == "WRITE" {
            // todo
        }
    })
    conf.WatchConfig()

    return &Config{
        adapter: conf,
    }
}

// 事件
func (c *Config) OnConfigChange(f func(string)) interfaces.Config {
    // 事件
    c.adapter.OnConfigChange(func(changeEvent fsnotify.Event) {
        opString := changeEvent.Op.String()
        f(opString)
    })

    return c
}

// 允许 clone 一个相同功能的结构体
func (c *Config) Clone(fileName string) interfaces.Config {
    // 这里存在一个深拷贝，需要注意，避免拷贝的结构体操作对原始结构体造成影响
    var config = *c
    var configViper = *(c.adapter)
    (&config).adapter = &configViper

    (&config).adapter.SetConfigName(fileName)
    if err := (&config).adapter.ReadInConfig(); err != nil {
        log.Fatal("配置初始化失败")
    }

    return &config
}

// Get 一个原始值
func (c *Config) Get(keyName string) interface{} {
    value := c.adapter.Get(keyName)
    return value
}

// GetString
func (c *Config) GetString(keyName string) string {
    value := c.adapter.GetString(keyName)
    return value
}

// GetBool
func (c *Config) GetBool(keyName string) bool {
    value := c.adapter.GetBool(keyName)
    return value
}

// GetInt
func (c *Config) GetInt(keyName string) int {
    value := c.adapter.GetInt(keyName)
    return value
}

// GetInt32
func (c *Config) GetInt32(keyName string) int32 {
    value := c.adapter.GetInt32(keyName)
    return value
}

// GetInt64
func (c *Config) GetInt64(keyName string) int64 {
    value := c.adapter.GetInt64(keyName)
    return value
}

// float64
func (c *Config) GetFloat64(keyName string) float64 {
    value := c.adapter.GetFloat64(keyName)
    return value
}

// GetDuration
func (c *Config) GetDuration(keyName string) time.Duration {
    value := c.adapter.GetDuration(keyName)
    return value
}

// GetStringSlice
func (c *Config) GetStringSlice(keyName string) []string {
    value := c.adapter.GetStringSlice(keyName)
    return value
}

// GetStringMap
func (c *Config) GetStringMap(keyName string) map[string]interface{} {
    value := c.adapter.GetStringMap(keyName)
    return value
}

// GetStringMapString
func (c *Config) GetStringMapString(keyName string) map[string]string {
    value := c.adapter.GetStringMapString(keyName)
    return value
}
