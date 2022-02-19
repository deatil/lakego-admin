package viper

import (
    "time"

    "github.com/spf13/viper"
    "github.com/fsnotify/fsnotify"

    "github.com/deatil/lakego-doak/lakego/support/path"
    "github.com/deatil/lakego-doak/lakego/config/adapter"
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

    // 路径
    path string
}

// 设置读取文件
func (this *Viper) Init() {
    conf := viper.New()

    this.conf = conf

    // 环境变量
    this.conf.AutomaticEnv()
    this.conf.AllowEmptyEnv(true)

    // 环境变量前缀
    this.conf.SetEnvPrefix("APP")
}

// 设置文件夹
func (this *Viper) WithPath(path string) {
    // 配置文件所在目录
    this.path = path
}

// 配置路径
func (this *Viper) WithConfigName(path string, name string, typ string) {
    // 配置文件所在目录
    this.conf.AddConfigPath(path)

    this.conf.SetConfigName(name)

    this.conf.SetConfigType(typ)

    // 合并配置
    this.conf.MergeInConfig()
}

// 配置文件
func (this *Viper) WithConfigFile(file string) {
    // 指定配置文件路径
    this.conf.SetConfigFile(path.FormatPath(file))

    // 合并配置
    this.conf.MergeInConfig()
}

// 要读取的文件
func (this *Viper) WithFile(fileName ...string) {
    /*
    // 配置里读取
    if err := this.conf.ReadInConfig(); err != nil {
        panic("配置初始化失败：" + err.Error())
    }
    */

    // 设置配置文件类型(后缀)为 yml
    nameType := ""
    if len(fileName) > 1 {
        nameType = fileName[1]
    } else {
        nameType = "yml"
    }

    if len(fileName) > 0 {
        // 导入自定义配置
        configFiles := adapter.NewPathInstance().GetPath(fileName[0])
        if len(configFiles) > 0 {
            for _, configFile := range configFiles {
                // 指定配置文件路径
                this.WithConfigFile(path.FormatPath(configFile))
            }
        }

        this.WithConfigName(this.path, fileName[0], nameType)
    }

    this.conf.WatchConfig()
}

// 设置默认值
func (this *Viper) SetDefault(keyName string, value interface{}) {
    this.conf.SetDefault(keyName, value)
}

// 设置
func (this *Viper) Set(keyName string, value interface{}) {
    this.conf.Set(keyName, value)
}

// 是否设置
func (this *Viper) IsSet(keyName string) bool {
    return this.conf.IsSet(keyName)
}

// Get 一个原始值
func (this *Viper) Get(keyName string) interface{} {
    value := this.conf.Get(keyName)
    return value
}

// GetString
func (this *Viper) GetString(keyName string) string {
    value := this.conf.GetString(keyName)
    return value
}

// GetBool
func (this *Viper) GetBool(keyName string) bool {
    value := this.conf.GetBool(keyName)
    return value
}

// GetInt
func (this *Viper) GetInt(keyName string) int {
    value := this.conf.GetInt(keyName)
    return value
}

// GetInt32
func (this *Viper) GetInt32(keyName string) int32 {
    value := this.conf.GetInt32(keyName)
    return value
}

// GetInt64
func (this *Viper) GetInt64(keyName string) int64 {
    value := this.conf.GetInt64(keyName)
    return value
}

// GetUint
func (this *Viper) GetUint(keyName string) uint {
    value := this.conf.GetUint(keyName)
    return value
}

// GetUint32
func (this *Viper) GetUint32(keyName string) uint32 {
    value := this.conf.GetUint32(keyName)
    return value
}

// GetUint64
func (this *Viper) GetUint64(keyName string) uint64 {
    value := this.conf.GetUint64(keyName)
    return value
}

// float64
func (this *Viper) GetFloat64(keyName string) float64 {
    value := this.conf.GetFloat64(keyName)
    return value
}

// GetTime
func (this *Viper) GetTime(keyName string) time.Time {
    value := this.conf.GetTime(keyName)
    return value
}

// GetDuration
func (this *Viper) GetDuration(keyName string) time.Duration {
    value := this.conf.GetDuration(keyName)
    return value
}

// GetIntSlice
func (this *Viper) GetIntSlice(keyName string) []int {
    value := this.conf.GetIntSlice(keyName)
    return value
}

// GetStringSlice
func (this *Viper) GetStringSlice(keyName string) []string {
    value := this.conf.GetStringSlice(keyName)
    return value
}

// GetStringMap
func (this *Viper) GetStringMap(keyName string) map[string]interface{} {
    value := this.conf.GetStringMap(keyName)
    return value
}

// GetStringMapString
func (this *Viper) GetStringMapString(keyName string) map[string]string {
    value := this.conf.GetStringMapString(keyName)
    return value
}

// GetStringMapStringSlice
func (this *Viper) GetStringMapStringSlice(keyName string) map[string][]string {
    value := this.conf.GetStringMapStringSlice(keyName)
    return value
}

// GetSizeInBytes
func (this *Viper) GetSizeInBytes(keyName string) uint {
    value := this.conf.GetSizeInBytes(keyName)
    return value
}

// 事件
func (this *Viper) OnConfigChange(f func(string)) {
    // 事件
    this.conf.OnConfigChange(func(changeEvent fsnotify.Event) {
        opString := changeEvent.Op.String()
        f(opString)
    })

    /*
    this.conf.OnConfigChange(func(changeEvent fsnotify.Event) {
        if changeEvent.Op.String() == "WRITE" {
            //
        }
    })
    */
}
