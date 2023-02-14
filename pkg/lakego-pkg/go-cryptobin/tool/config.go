package tool

import (
    "time"
    "encoding/json"
)

func NewConfig() *Config {
    return &Config{
        data: make(map[string]any),
    }
}

/**
 * 配置
 *
 * @create 2023-2-13
 * @author deatil
 */
type Config struct {
    data map[string]any
}

// 设置
func (this *Config) WithData(data map[string]any) *Config {
    this.data = data

    return this
}

// 设置
func (this *Config) Set(name string, data any) *Config {
    this.data[name] = data

    return this
}

func (this *Config) Has(name string) bool {
    if _, ok := this.data[name]; ok {
        return true
    }

    return false
}

func (this *Config) Get(name string) any {
    if data, ok := this.data[name]; ok {
        return data
    }

    return nil
}

func (this *Config) GetString(name string) string {
    if data, ok := this.Get(name).(string); ok {
        return data
    }

    return ""
}

func (this *Config) GetBytes(name string) []byte {
    if data, ok := this.Get(name).([]byte); ok {
        return data
    }

    return nil
}

func (this *Config) GetUint(name string) uint {
    if data, ok := this.Get(name).(uint); ok {
        return data
    }

    return 0
}

func (this *Config) GetUint8(name string) uint8 {
    if data, ok := this.Get(name).(uint8); ok {
        return data
    }

    return 0
}

func (this *Config) GetUint16(name string) uint16 {
    if data, ok := this.Get(name).(uint16); ok {
        return data
    }

    return 0
}

func (this *Config) GetUint32(name string) uint32 {
    if data, ok := this.Get(name).(uint32); ok {
        return data
    }

    return 0
}

func (this *Config) GetUint64(name string) uint64 {
    if data, ok := this.Get(name).(uint64); ok {
        return data
    }

    return 0
}

func (this *Config) GetInt(name string) int {
    if data, ok := this.Get(name).(int); ok {
        return data
    }

    return 0
}

func (this *Config) GetInt8(name string) int8 {
    if data, ok := this.Get(name).(int8); ok {
        return data
    }

    return 0
}

func (this *Config) GetInt16(name string) int16 {
    if data, ok := this.Get(name).(int16); ok {
        return data
    }

    return 0
}

func (this *Config) GetInt32(name string) int32 {
    if data, ok := this.Get(name).(int32); ok {
        return data
    }

    return 0
}

func (this *Config) GetInt64(name string) int64 {
    if data, ok := this.Get(name).(int64); ok {
        return data
    }

    return 0
}

func (this *Config) GetFloat32(name string) float32 {
    if data, ok := this.Get(name).(float32); ok {
        return data
    }

    return 0
}

func (this *Config) GetFloat64(name string) float64 {
    if data, ok := this.Get(name).(float64); ok {
        return data
    }

    return 0
}

func (this *Config) GetBool(name string) bool {
    if data, ok := this.Get(name).(bool); ok {
        return data
    }

    return false
}

func (this *Config) GetTime(name string) time.Time {
    if data, ok := this.Get(name).(time.Time); ok {
        return data
    }

    return time.Time{}
}

func (this *Config) GetDuration(name string) time.Duration {
    if data, ok := this.Get(name).(time.Duration); ok {
        return data
    }

    return time.Duration(0)
}

func (this *Config) GetStringMapString(name string) map[string]string {
    if data, ok := this.Get(name).(map[string]string); ok {
        return data
    }

    return make(map[string]string)
}

func (this *Config) GetStringMapStringSlice(name string) map[string][]string {
    if data, ok := this.Get(name).(map[string][]string); ok {
        return data
    }

    return make(map[string][]string)
}

func (this *Config) GetStringMapBool(name string) map[string]bool {
    if data, ok := this.Get(name).(map[string]bool); ok {
        return data
    }

    return make(map[string]bool)
}

func (this *Config) GetStringMapInt(name string) map[string]int {
    if data, ok := this.Get(name).(map[string]int); ok {
        return data
    }

    return make(map[string]int)
}

func (this *Config) GetStringMapInt64(name string) map[string]int64 {
    if data, ok := this.Get(name).(map[string]int64); ok {
        return data
    }

    return make(map[string]int64)
}

func (this *Config) GetStringMap(name string) map[string]any {
    if data, ok := this.Get(name).(map[string]any); ok {
        return data
    }

    return make(map[string]any)
}

func (this *Config) GetSlice(name string) []any {
    if data, ok := this.Get(name).([]any); ok {
        return data
    }

    return make([]any, 0)
}

func (this *Config) GetBoolSlice(name string) []bool {
    if data, ok := this.Get(name).([]bool); ok {
        return data
    }

    return make([]bool, 0)
}

func (this *Config) GetStringSlice(name string) []string {
    if data, ok := this.Get(name).([]string); ok {
        return data
    }

    return make([]string, 0)
}

func (this *Config) GetIntSlice(name string) []int {
    if data, ok := this.Get(name).([]int); ok {
        return data
    }

    return make([]int, 0)
}

func (this *Config) GetDurationSlice(name string) []time.Duration {
    if data, ok := this.Get(name).([]time.Duration); ok {
        return data
    }

    return make([]time.Duration, 0)
}

func (this *Config) All() map[string]any {
    return this.data
}

func (this *Config) String() string {
    data, _ := json.Marshal(this.data)

    return string(data)
}

func (this *Config) Reset() {
    this.data = make(map[string]any)
}
