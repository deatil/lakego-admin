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
func (this *Adapter) WithPath(path string) {
    panic("方法没有实现")
}

// 设置读取文件
func (this *Adapter) WithFile(fileName ...string) {
    panic("方法没有实现")
}

// 设置默认值
func (this *Adapter) SetDefault(keyName string, value interface{}) {
    panic("方法没有实现")
}

// 设置
func (this *Adapter) Set(keyName string, value interface{}) {
    panic("方法没有实现")
}

// 是否设置
func (this *Adapter) IsSet(keyName string) bool {
    panic("方法没有实现")
}

// Get 一个原始值
func (this *Adapter) Get(keyName string) interface{} {
    panic("方法没有实现")
}

// GetString
func (this *Adapter) GetString(keyName string) string {
    panic("方法没有实现")
}

// GetBool
func (this *Adapter) GetBool(keyName string) bool {
    panic("方法没有实现")
}

// GetInt
func (this *Adapter) GetInt(keyName string) int {
    panic("方法没有实现")
}

// GetInt32
func (this *Adapter) GetInt32(keyName string) int32 {
    panic("方法没有实现")
}

// GetInt64
func (this *Adapter) GetInt64(keyName string) int64 {
    panic("方法没有实现")
}

// float64
func (this *Adapter) GetFloat64(keyName string) float64 {
    panic("方法没有实现")
}

// GetTime
func (this *Adapter) GetTime(keyName string) time.Time {
    panic("方法没有实现")
}

// GetDuration
func (this *Adapter) GetDuration(keyName string) time.Duration {
    panic("方法没有实现")
}

// GetStringSlice
func (this *Adapter) GetStringSlice(keyName string) []string {
    panic("方法没有实现")
}

// GetStringMap
func (this *Adapter) GetStringMap(keyName string) map[string]interface{} {
    panic("方法没有实现")
}

// GetStringMapString
func (this *Adapter) GetStringMapString(keyName string) map[string]string {
    panic("方法没有实现")
}

// 事件
func (this *Adapter) OnConfigChange(f func(string)) {
    panic("方法没有实现")
}

