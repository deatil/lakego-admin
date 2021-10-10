package viper

import (
    "time"

    "github.com/spf13/viper"
    "github.com/fsnotify/fsnotify"

    "github.com/deatil/lakego-admin/lakego/config/adapter"
)

/**
 * Viper 适配器
 *
 * @create 2021-9-25
 * @author deatil
 */
type Viper struct {
   adapter.Adapter

   conf *viper.Viper
}

// 设置读取文件
func (v *Viper) Init() {
    conf := viper.New()

    v.conf = conf
}

// 设置文件夹
func (v *Viper) WithPath(path string) {
    // 配置文件所在目录
    v.conf.AddConfigPath(path)
}

// 要读取的文件
func (v *Viper) WithFile(fileName ...string) {
    // 设置根目录
    v.conf.AddConfigPath(".")

    // 需要读取的文件名,默认为：config
    if len(fileName) > 0 {
        v.conf.SetConfigName(fileName[0])
    } else {
        v.conf.SetConfigName("config")
    }

    // 设置配置文件类型(后缀)为 yml
    if len(fileName) > 1 {
        v.conf.SetConfigType(fileName[1])
    } else {
        v.conf.SetConfigType("yml")
    }

    // 配置里读取
    if err := v.conf.ReadInConfig(); err != nil {
        panic("配置初始化失败：" + err.Error())
    }

    // 环境变量
    v.conf.AutomaticEnv()
    v.conf.AllowEmptyEnv(true)

    // 事件
    v.conf.OnConfigChange(func(changeEvent fsnotify.Event) {
        if changeEvent.Op.String() == "WRITE" {
            //
        }
    })

    v.conf.WatchConfig()
}

// 设置默认值
func (v *Viper) SetDefault(keyName string, value interface{}) {
    v.conf.SetDefault(keyName, value)
}

// 设置
func (v *Viper) Set(keyName string, value interface{}) {
    v.conf.Set(keyName, value)
}

// 是否设置
func (v *Viper) IsSet(keyName string) bool {
    return v.conf.IsSet(keyName)
}

// Get 一个原始值
func (v *Viper) Get(keyName string) interface{} {
    value := v.conf.Get(keyName)
    return value
}

// GetString
func (v *Viper) GetString(keyName string) string {
    value := v.conf.GetString(keyName)
    return value
}

// GetBool
func (v *Viper) GetBool(keyName string) bool {
    value := v.conf.GetBool(keyName)
    return value
}

// GetInt
func (v *Viper) GetInt(keyName string) int {
    value := v.conf.GetInt(keyName)
    return value
}

// GetInt32
func (v *Viper) GetInt32(keyName string) int32 {
    value := v.conf.GetInt32(keyName)
    return value
}

// GetInt64
func (v *Viper) GetInt64(keyName string) int64 {
    value := v.conf.GetInt64(keyName)
    return value
}

// float64
func (v *Viper) GetFloat64(keyName string) float64 {
    value := v.conf.GetFloat64(keyName)
    return value
}

// GetTime
func (v *Viper) GetTime(keyName string) time.Time {
    value := v.conf.GetTime(keyName)
    return value
}

// GetDuration
func (v *Viper) GetDuration(keyName string) time.Duration {
    value := v.conf.GetDuration(keyName)
    return value
}

// GetStringSlice
func (v *Viper) GetStringSlice(keyName string) []string {
    value := v.conf.GetStringSlice(keyName)
    return value
}

// GetStringMap
func (v *Viper) GetStringMap(keyName string) map[string]interface{} {
    value := v.conf.GetStringMap(keyName)
    return value
}

// GetStringMapString
func (v *Viper) GetStringMapString(keyName string) map[string]string {
    value := v.conf.GetStringMapString(keyName)
    return value
}

// 事件
func (v *Viper) OnConfigChange(f func(string)) {
    // 事件
    v.conf.OnConfigChange(func(changeEvent fsnotify.Event) {
        opString := changeEvent.Op.String()
        f(opString)
    })
}
