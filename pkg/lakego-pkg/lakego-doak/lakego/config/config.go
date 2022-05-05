package config

import (
    "time"

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

// 添加适配器
func (this *Config) WithAdapter(adapter interfaces.Adapter) *Config {
    this.adapter = adapter

    return this
}

// 获取适配器
func (this *Config) GetAdapter() interfaces.Adapter {
    return this.adapter
}

// 设置文件夹
func (this *Config) WithPath(path string) *Config {
    this.adapter.WithPath(path)

    return this
}

// 设置读取文件
func (this *Config) WithFile(fileName ...string) *Config {
    this.adapter.WithFile(fileName...)

    return this
}

// 设置读取文件
func (this *Config) Use(fileName ...string) *Config {
    this.WithFile(fileName...)

    return this
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
    return this.adapter.GetString(keyName)
}

// GetBool
func (this *Config) GetBool(keyName string) bool {
    return this.adapter.GetBool(keyName)
}

// GetInt
func (this *Config) GetInt(keyName string) int {
    return this.adapter.GetInt(keyName)
}

// GetInt32
func (this *Config) GetInt32(keyName string) int32 {
    return this.adapter.GetInt32(keyName)
}

// GetInt64
func (this *Config) GetInt64(keyName string) int64 {
    return this.adapter.GetInt64(keyName)
}

// GetUint
func (this *Config) GetUint(keyName string) uint {
    return this.adapter.GetUint(keyName)
}

// GetUint32
func (this *Config) GetUint32(keyName string) uint32 {
    return this.adapter.GetUint32(keyName)
}

// GetUint64
func (this *Config) GetUint64(keyName string) uint64 {
    return this.adapter.GetUint64(keyName)
}

// float64
func (this *Config) GetFloat64(keyName string) float64 {
    return this.adapter.GetFloat64(keyName)
}

// GetTime
func (this *Config) GetTime(keyName string) time.Time {
    return this.adapter.GetTime(keyName)
}

// GetDuration
func (this *Config) GetDuration(keyName string) time.Duration {
    return this.adapter.GetDuration(keyName)
}

// GetIntSlice
func (this *Config) GetIntSlice(keyName string) []int {
    return this.adapter.GetIntSlice(keyName)
}

// GetStringSlice
func (this *Config) GetStringSlice(keyName string) []string {
    return this.adapter.GetStringSlice(keyName)
}

// GetStringMap
func (this *Config) GetStringMap(keyName string) map[string]any {
    return this.adapter.GetStringMap(keyName)
}

// GetStringMapString
func (this *Config) GetStringMapString(keyName string) map[string]string {
    return this.adapter.GetStringMapString(keyName)
}

// GetStringMapStringSlice
func (this *Config) GetStringMapStringSlice(keyName string) map[string][]string {
    return this.adapter.GetStringMapStringSlice(keyName)
}

// GetSizeInBytes
func (this *Config) GetSizeInBytes(keyName string) uint {
    return this.adapter.GetSizeInBytes(keyName)
}

// 事件
func (this *Config) OnConfigChange(f func(string)) *Config {
    // 事件
    this.adapter.OnConfigChange(f)

    return this
}

