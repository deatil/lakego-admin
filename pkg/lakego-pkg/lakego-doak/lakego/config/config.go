package config

import (
    "time"
    "github.com/deatil/go-goch/goch"

    "github.com/deatil/lakego-doak/lakego/config/interfaces"
)

/**
 * 配置
 *
 * @create 2021-6-19
 * @author deatil
 */
type Config struct {
    // 适配器
    adapter interfaces.Adapter
}

// 构造函数
func New(adapter interfaces.Adapter) *Config {
    return &Config{
        adapter: adapter,
    }
}

// 添加适配器
func (this *Config) WithAdapter(adapter interfaces.Adapter) *Config {
    this.adapter = adapter

    return this
}

// 获取适配器
func (this *Config) GetAdapter() interfaces.Adapter {
    return this.adapter
}

// 设置默认值
func (this *Config) SetDefault(keyName string, value any) *Config {
    this.adapter.SetDefault(keyName, value)

    return this
}

// 设置
func (this *Config) Set(keyName string, value any) *Config {
    this.adapter.Set(keyName, value)

    return this
}

// 是否设置
func (this *Config) IsSet(keyName string) bool {
    return this.adapter.IsSet(keyName)
}

// Get 一个原始值
func (this *Config) Get(keyName string) any {
    return this.adapter.Get(keyName)
}

// GetString
func (this *Config) GetString(keyName string) string {
    return goch.ToString(this.Get(keyName))
}

// GetBool
func (this *Config) GetBool(keyName string) bool {
    return goch.ToBool(this.Get(keyName))
}

// GetInt
func (this *Config) GetInt(keyName string) int {
    return goch.ToInt(this.Get(keyName))
}

// GetInt32
func (this *Config) GetInt32(keyName string) int32 {
    return goch.ToInt32(this.Get(keyName))
}

// GetInt64
func (this *Config) GetInt64(keyName string) int64 {
    return goch.ToInt64(this.Get(keyName))
}

// GetUint
func (this *Config) GetUint(keyName string) uint {
    return goch.ToUint(this.Get(keyName))
}

// GetUint32
func (this *Config) GetUint32(keyName string) uint32 {
    return goch.ToUint32(this.Get(keyName))
}

// GetUint64
func (this *Config) GetUint64(keyName string) uint64 {
    return goch.ToUint64(this.Get(keyName))
}

// float64
func (this *Config) GetFloat64(keyName string) float64 {
    return goch.ToFloat64(this.Get(keyName))
}

// GetTime
func (this *Config) GetTime(keyName string) time.Time {
    return goch.ToTime(this.Get(keyName))
}

// GetDuration
func (this *Config) GetDuration(keyName string) time.Duration {
    return goch.ToDuration(this.Get(keyName))
}

// GetIntSlice
func (this *Config) GetIntSlice(keyName string) []int {
    return goch.ToIntSlice(this.Get(keyName))
}

// GetStringSlice
func (this *Config) GetStringSlice(keyName string) []string {
    return goch.ToStringSlice(this.Get(keyName))
}

// GetStringMap
func (this *Config) GetStringMap(keyName string) map[string]any {
    return goch.ToStringMap(this.Get(keyName))
}

// GetStringMapString
func (this *Config) GetStringMapString(keyName string) map[string]string {
    return goch.ToStringMapString(this.Get(keyName))
}

// GetStringMapStringSlice
func (this *Config) GetStringMapStringSlice(keyName string) map[string][]string {
    return goch.ToStringMapStringSlice(this.Get(keyName))
}

// 事件
func (this *Config) OnConfigChange(f func(string)) *Config {
    // 事件
    this.adapter.OnConfigChange(f)

    return this
}

