package config

import (
    "time"

    "github.com/deatil/lakego-admin/lakego/config/interfaces"
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
func (this *Config) SetDefault(keyName string, value interface{}) *Config {
    this.adapter.SetDefault(keyName, value)

    return this
}

// 设置
func (this *Config) Set(keyName string, value interface{}) *Config {
    this.adapter.Set(keyName, value)

    return this
}

// 是否设置
func (this *Config) IsSet(keyName string) bool {
    return this.adapter.IsSet(keyName)
}

// Get 一个原始值
func (this *Config) Get(keyName string) interface{} {
    value := this.adapter.Get(keyName)

    return value
}

// GetString
func (this *Config) GetString(keyName string) string {
    value := this.adapter.GetString(keyName)

    return value
}

// GetBool
func (this *Config) GetBool(keyName string) bool {
    value := this.adapter.GetBool(keyName)

    return value
}

// GetInt
func (this *Config) GetInt(keyName string) int {
    value := this.adapter.GetInt(keyName)

    return value
}

// GetInt32
func (this *Config) GetInt32(keyName string) int32 {
    value := this.adapter.GetInt32(keyName)

    return value
}

// GetInt64
func (this *Config) GetInt64(keyName string) int64 {
    value := this.adapter.GetInt64(keyName)

    return value
}

// float64
func (this *Config) GetFloat64(keyName string) float64 {
    value := this.adapter.GetFloat64(keyName)

    return value
}

// GetTime
func (this *Config) GetTime(keyName string) time.Time {
    value := this.adapter.GetTime(keyName)

    return value
}

// GetDuration
func (this *Config) GetDuration(keyName string) time.Duration {
    value := this.adapter.GetDuration(keyName)

    return value
}

// GetStringSlice
func (this *Config) GetStringSlice(keyName string) []string {
    value := this.adapter.GetStringSlice(keyName)

    return value
}

// GetStringMap
func (this *Config) GetStringMap(keyName string) map[string]interface{} {
    value := this.adapter.GetStringMap(keyName)

    return value
}

// GetStringMapString
func (this *Config) GetStringMapString(keyName string) map[string]string {
    value := this.adapter.GetStringMapString(keyName)

    return value
}

// 事件
func (this *Config) OnConfigChange(f func(string)) *Config {
    // 事件
    this.adapter.OnConfigChange(f)

    return this
}

