package adapter

import (
    "time"
)

/**
 * 适配器
 *
 * @create 2021-9-25
 * @author deatil
 */
type Adapter struct {}

// 设置文件夹
func (a *Adapter) WithPath(path string) {
    panic("方法没有实现")
}

// 设置读取文件
func (a *Adapter) WithFile(fileName ...string) {
    panic("方法没有实现")
}

// 设置默认值
func (a *Adapter) SetDefault(keyName string, value interface{}) {
    panic("方法没有实现")
}

// 设置
func (a *Adapter) Set(keyName string, value interface{}) {
    panic("方法没有实现")
}

// 是否设置
func (a *Adapter) IsSet(keyName string) bool {
    panic("方法没有实现")
}

// Get 一个原始值
func (a *Adapter) Get(keyName string) interface{} {
    panic("方法没有实现")
}

// GetString
func (a *Adapter) GetString(keyName string) string {
    panic("方法没有实现")
}

// GetBool
func (a *Adapter) GetBool(keyName string) bool {
    panic("方法没有实现")
}

// GetInt
func (a *Adapter) GetInt(keyName string) int {
    panic("方法没有实现")
}

// GetInt32
func (a *Adapter) GetInt32(keyName string) int32 {
    panic("方法没有实现")
}

// GetInt64
func (a *Adapter) GetInt64(keyName string) int64 {
    panic("方法没有实现")
}

// float64
func (a *Adapter) GetFloat64(keyName string) float64 {
    panic("方法没有实现")
}

// GetTime
func (a *Adapter) GetTime(keyName string) time.Time {
    panic("方法没有实现")
}

// GetDuration
func (a *Adapter) GetDuration(keyName string) time.Duration {
    panic("方法没有实现")
}

// GetStringSlice
func (a *Adapter) GetStringSlice(keyName string) []string {
    panic("方法没有实现")
}

// GetStringMap
func (a *Adapter) GetStringMap(keyName string) map[string]interface{} {
    panic("方法没有实现")
}

// GetStringMapString
func (a *Adapter) GetStringMapString(keyName string) map[string]string {
    panic("方法没有实现")
}

// 事件
func (a *Adapter) OnConfigChange(f func(string)) {
    panic("方法没有实现")
}

