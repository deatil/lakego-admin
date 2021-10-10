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
func (c *Config) WithAdapter(adapter interfaces.Adapter) *Config {
    c.adapter = adapter

    return c
}

// 获取适配器
func (c *Config) GetAdapter() interfaces.Adapter {
    return c.adapter
}

// 设置读取文件
func (c *Config) WithFile(fileName ...string) *Config {
    c.adapter.WithFile(fileName...)

    return c
}

// 设置默认值
func (c *Config) SetDefault(keyName string, value interface{}) *Config {
    c.adapter.SetDefault(keyName, value)

    return c
}

// 设置
func (c *Config) Set(keyName string, value interface{}) *Config {
    c.adapter.Set(keyName, value)

    return c
}

// 是否设置
func (c *Config) IsSet(keyName string) bool {
    return c.adapter.IsSet(keyName)
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

// GetTime
func (c *Config) GetTime(keyName string) time.Time {
    value := c.adapter.GetTime(keyName)

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

// 事件
func (c *Config) OnConfigChange(f func(string)) *Config {
    // 事件
    c.adapter.OnConfigChange(f)

    return c
}

