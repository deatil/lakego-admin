package viper

import (
    "time"
    "bytes"
    "strings"

    "github.com/spf13/viper"
    "github.com/fsnotify/fsnotify"

    "github.com/deatil/lakego-doak/lakego/path"
    "github.com/deatil/lakego-doak/lakego/config/adapter"
)

// 构造函数
func New() *Viper {
    v := &Viper{}
    v.viper = viper.New()

    return v
}

/**
 * Viper 适配器
 *
 * @create 2021-9-25
 * @author deatil
 */
type Viper struct {
    adapter.Adapter

    viper *viper.Viper

    // 路径
    path string
}

// 环境变量前缀
func (this *Viper) SetEnvPrefix(prefix string) {
    this.viper.SetEnvPrefix(prefix)
    this.viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
}

// 环境变量
func (this *Viper) AutomaticEnv() {
    this.viper.AutomaticEnv()
    this.viper.AllowEmptyEnv(true)
}

// 设置文件夹
func (this *Viper) WithPath(path string) {
    // 配置文件所在目录
    this.path = path
}

// 配置路径
func (this *Viper) setConfigName(path string, name string, typ string) {
    // 配置文件所在目录
    this.viper.AddConfigPath(path)

    this.viper.SetConfigName(name)

    this.viper.SetConfigType(typ)

    // 合并配置
    this.viper.MergeInConfig()
}

// 配置文件
func (this *Viper) setConfigFile(file string) {
    // 指定配置文件路径
    this.viper.SetConfigFile(path.FormatPath(file))

    // 合并配置
    this.viper.MergeInConfig()
}

// 要读取的文件
func (this *Viper) WithFile(fileName ...string) {
    /*
    // 配置里读取
    if err := this.viper.ReadInConfig(); err != nil {
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
        configFiles := adapter.GetPath(fileName[0])
        if len(configFiles) > 0 {
            for _, configFile := range configFiles {
                // 指定配置文件路径
                this.setConfigFile(path.FormatPath(configFile))
            }
        }

        this.setConfigName(this.path, fileName[0], nameType)
    }

    this.viper.WatchConfig()
}

// 要读取的数据
func (this *Viper) WithBytes(data []byte, typ string) {
    this.viper.SetConfigType(typ)

    this.viper.ReadConfig(bytes.NewBuffer(data))

    // 合并配置
    this.viper.MergeInConfig()
}

// 获取
func (this *Viper) GetViper() *viper.Viper {
    return this.viper
}

// 设置默认值
func (this *Viper) SetDefault(keyName string, value any) {
    this.viper.SetDefault(keyName, value)
}

// 设置
func (this *Viper) Set(keyName string, value any) {
    this.viper.Set(keyName, value)
}

// 是否设置
func (this *Viper) IsSet(keyName string) bool {
    return this.viper.IsSet(keyName)
}

// Get 一个原始值
func (this *Viper) Get(keyName string) any {
    value := this.viper.Get(keyName)
    return value
}

// 事件
func (this *Viper) OnConfigChange(f func(string)) {
    // 事件
    this.viper.OnConfigChange(func(changeEvent fsnotify.Event) {
        // WRITE
        opString := changeEvent.Op.String()
        f(opString)
    })
}

// ================================================

// GetString
func (this *Viper) GetString(keyName string) string {
    value := this.viper.GetString(keyName)
    return value
}

// GetBool
func (this *Viper) GetBool(keyName string) bool {
    value := this.viper.GetBool(keyName)
    return value
}

// GetInt
func (this *Viper) GetInt(keyName string) int {
    value := this.viper.GetInt(keyName)
    return value
}

// GetInt32
func (this *Viper) GetInt32(keyName string) int32 {
    value := this.viper.GetInt32(keyName)
    return value
}

// GetInt64
func (this *Viper) GetInt64(keyName string) int64 {
    value := this.viper.GetInt64(keyName)
    return value
}

// GetUint
func (this *Viper) GetUint(keyName string) uint {
    value := this.viper.GetUint(keyName)
    return value
}

// GetUint32
func (this *Viper) GetUint32(keyName string) uint32 {
    value := this.viper.GetUint32(keyName)
    return value
}

// GetUint64
func (this *Viper) GetUint64(keyName string) uint64 {
    value := this.viper.GetUint64(keyName)
    return value
}

// float64
func (this *Viper) GetFloat64(keyName string) float64 {
    value := this.viper.GetFloat64(keyName)
    return value
}

// GetTime
func (this *Viper) GetTime(keyName string) time.Time {
    value := this.viper.GetTime(keyName)
    return value
}

// GetDuration
func (this *Viper) GetDuration(keyName string) time.Duration {
    value := this.viper.GetDuration(keyName)
    return value
}

// GetIntSlice
func (this *Viper) GetIntSlice(keyName string) []int {
    value := this.viper.GetIntSlice(keyName)
    return value
}

// GetStringSlice
func (this *Viper) GetStringSlice(keyName string) []string {
    value := this.viper.GetStringSlice(keyName)
    return value
}

// GetStringMap
func (this *Viper) GetStringMap(keyName string) map[string]any {
    value := this.viper.GetStringMap(keyName)
    return value
}

// GetStringMapString
func (this *Viper) GetStringMapString(keyName string) map[string]string {
    value := this.viper.GetStringMapString(keyName)
    return value
}

// GetStringMapStringSlice
func (this *Viper) GetStringMapStringSlice(keyName string) map[string][]string {
    value := this.viper.GetStringMapStringSlice(keyName)
    return value
}

// GetSizeInBytes, 暂未使用
func (this *Viper) GetSizeInBytes(keyName string) uint {
    value := this.viper.GetSizeInBytes(keyName)
    return value
}
