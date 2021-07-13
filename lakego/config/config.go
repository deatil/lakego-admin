package config

import (
    "log"
    "time"

    "github.com/fsnotify/fsnotify"
    "github.com/spf13/viper"

    "lakego-admin/lakego/support/path"
    "lakego-admin/lakego/container"
    "lakego-admin/lakego/config/interfaces"
)

var lastChangeTime time.Time
var basePath string
var configKeyPrefix string = "Config_"
var configPath string = "/config"

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
    lastChangeTime = time.Now()

    // 程序根目录
    basePath = path.GetBasePath()
}

// 参数设置为可变参数的文件名，这样参数就可以不需要传递，如果传递了多个，我们只取第一个参数作为配置文件名
func New(fileName ...string) interfaces.ConfigInterface {
    config := viper.New()

    // 配置文件所在目录
    config.AddConfigPath(basePath + configPath)

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

    return &configMap{
        config,
    }
}

// 程序根目录
func (y *configMap) GetBasePath() string {
    return basePath
}

// 监听文件变化
func (y *configMap) ConfigFileChangeListen() {
    y.viper.OnConfigChange(func(changeEvent fsnotify.Event) {
        if time.Now().Sub(lastChangeTime).Seconds() >= 1 {
            if changeEvent.Op.String() == "WRITE" {
                y.clearCache()
                lastChangeTime = time.Now()
            }
        }
    })
    y.viper.WatchConfig()
}

// 判断相关键是否已经缓存
func (y *configMap) keyIsCache(keyName string) bool {
    if _, exists := container.New().KeyIsExists(configKeyPrefix + keyName); exists {
        return true
    } else {
        return false
    }
}

// 对键值进行缓存
func (y *configMap) cache(keyName string, value interface{}) bool {
    return container.New().Set(configKeyPrefix + keyName, value)
}

// 通过键获取缓存的值
func (y *configMap) getValueFromCache(keyName string) interface{} {
    return container.New().Get(configKeyPrefix + keyName)
}

// 清空已经窜换的配置项信息
func (y *configMap) clearCache() {
    container.New().FuzzyDelete(configKeyPrefix)
}

// 允许 clone 一个相同功能的结构体
func (y *configMap) Clone(fileName string) interfaces.ConfigInterface {
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
    if y.keyIsCache(keyName) {
        return y.getValueFromCache(keyName)
    } else {
        value := y.viper.Get(keyName)
        y.cache(keyName, value)
        return value
    }
}

// GetString
func (y *configMap) GetString(keyName string) string {
    if y.keyIsCache(keyName) {
        return y.getValueFromCache(keyName).(string)
    } else {
        value := y.viper.GetString(keyName)
        y.cache(keyName, value)
        return value
    }
}

// GetBool
func (y *configMap) GetBool(keyName string) bool {
    if y.keyIsCache(keyName) {
        return y.getValueFromCache(keyName).(bool)
    } else {
        value := y.viper.GetBool(keyName)
        y.cache(keyName, value)
        return value
    }
}

// GetInt
func (y *configMap) GetInt(keyName string) int {
    if y.keyIsCache(keyName) {
        return y.getValueFromCache(keyName).(int)
    } else {
        value := y.viper.GetInt(keyName)
        y.cache(keyName, value)
        return value
    }
}

// GetInt32
func (y *configMap) GetInt32(keyName string) int32 {
    if y.keyIsCache(keyName) {
        return y.getValueFromCache(keyName).(int32)
    } else {
        value := y.viper.GetInt32(keyName)
        y.cache(keyName, value)
        return value
    }
}

// GetInt64
func (y *configMap) GetInt64(keyName string) int64 {
    if y.keyIsCache(keyName) {
        return y.getValueFromCache(keyName).(int64)
    } else {
        value := y.viper.GetInt64(keyName)
        y.cache(keyName, value)
        return value
    }
}

// float64
func (y *configMap) GetFloat64(keyName string) float64 {
    if y.keyIsCache(keyName) {
        return y.getValueFromCache(keyName).(float64)
    } else {
        value := y.viper.GetFloat64(keyName)
        y.cache(keyName, value)
        return value
    }
}

// GetDuration
func (y *configMap) GetDuration(keyName string) time.Duration {
    if y.keyIsCache(keyName) {
        return y.getValueFromCache(keyName).(time.Duration)
    } else {
        value := y.viper.GetDuration(keyName)
        y.cache(keyName, value)
        return value
    }
}

// GetStringSlice
func (y *configMap) GetStringSlice(keyName string) []string {
    if y.keyIsCache(keyName) {
        return y.getValueFromCache(keyName).([]string)
    } else {
        value := y.viper.GetStringSlice(keyName)
        y.cache(keyName, value)
        return value
    }
}

// GetStringMap
func (y *configMap) GetStringMap(keyName string) map[string]interface{} {
    if y.keyIsCache(keyName) {
        return y.getValueFromCache(keyName).(map[string]interface{})
    } else {
        value := y.viper.GetStringMap(keyName)
        y.cache(keyName, value)
        return value
    }
}

// GetStringMapString
func (y *configMap) GetStringMapString(keyName string) map[string]string {
    if y.keyIsCache(keyName) {
        return y.getValueFromCache(keyName).(map[string]string)
    } else {
        value := y.viper.GetStringMapString(keyName)
        y.cache(keyName, value)
        return value
    }
}
