package config

import (
    "log"
    "time"

    "github.com/fsnotify/fsnotify"
    "github.com/spf13/viper"

    "lakego-admin/lakego/support/path"
    "lakego-admin/lakego/config/interfaces"
)

var basePath string

/**
 * 配置
 *
 * @create 2021-6-19
 * @author deatil
 */
type configMap struct {
    viper *viper.Viper
}

func init() {
    // 程序根目录
    basePath = path.GetBasePath()
}

// 参数设置为可变参数的文件名
func New(fileName ...string) interfaces.Config {
    config := viper.New()

    // 配置文件夹
    configPath := basePath + "/config"

    // 配置文件所在目录
    config.AddConfigPath(configPath)

    // 需要读取的文件名,默认为：config
    if len(fileName) == 0 {
        config.SetConfigName("admin")
    } else {
        config.SetConfigName(fileName[0])
    }

    // 设置配置文件类型(后缀)为 yml
    if len(fileName) <= 1 {
        config.SetConfigType("yml")
    } else {
        config.SetConfigType(fileName[1])
    }

    if err := config.ReadInConfig(); err != nil {
        log.Fatal(err.Error())
    }

    // 设置根目录
    config.AddConfigPath(".")
    config.ReadInConfig()

    // 配置里读取
    _ = config.ReadInConfig()

    // 环境变量
    config.AutomaticEnv()
    config.AllowEmptyEnv(true)

    // 事件
    config.OnConfigChange(func(changeEvent fsnotify.Event) {
        if changeEvent.Op.String() == "WRITE" {
            // todo
        }
    })
    config.WatchConfig()

    return &configMap{
        config,
    }
}

// 程序根目录
func (y *configMap) GetBasePath() string {
    return basePath
}

// 允许 clone 一个相同功能的结构体
func (y *configMap) Clone(fileName string) interfaces.Config {
    // 这里存在一个深拷贝，需要注意，避免拷贝的结构体操作对原始结构体造成影响
    var config = *y
    var configViper = *(y.viper)
    (&config).viper = &configViper

    (&config).viper.SetConfigName(fileName)
    if err := (&config).viper.ReadInConfig(); err != nil {
        log.Fatal("配置初始化失败")
    }

    return &config
}

// Get 一个原始值
func (y *configMap) Get(keyName string) interface{} {
    value := y.viper.Get(keyName)
    return value
}

// GetString
func (y *configMap) GetString(keyName string) string {
    value := y.viper.GetString(keyName)
    return value
}

// GetBool
func (y *configMap) GetBool(keyName string) bool {
    value := y.viper.GetBool(keyName)
    return value
}

// GetInt
func (y *configMap) GetInt(keyName string) int {
    value := y.viper.GetInt(keyName)
    return value
}

// GetInt32
func (y *configMap) GetInt32(keyName string) int32 {
    value := y.viper.GetInt32(keyName)
    return value
}

// GetInt64
func (y *configMap) GetInt64(keyName string) int64 {
    value := y.viper.GetInt64(keyName)
    return value
}

// float64
func (y *configMap) GetFloat64(keyName string) float64 {
    value := y.viper.GetFloat64(keyName)
    return value
}

// GetDuration
func (y *configMap) GetDuration(keyName string) time.Duration {
    value := y.viper.GetDuration(keyName)
    return value
}

// GetStringSlice
func (y *configMap) GetStringSlice(keyName string) []string {
    value := y.viper.GetStringSlice(keyName)
    return value
}

// GetStringMap
func (y *configMap) GetStringMap(keyName string) map[string]interface{} {
    value := y.viper.GetStringMap(keyName)
    return value
}

// GetStringMapString
func (y *configMap) GetStringMapString(keyName string) map[string]string {
    value := y.viper.GetStringMapString(keyName)
    return value
}
