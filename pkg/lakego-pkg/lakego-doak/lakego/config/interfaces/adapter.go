package interfaces

import (
    "time"
)

/**
 * 适配器接口
 *
 * @create 2021-9-25
 * @author deatil
 */
type Adapter interface {
    // 设置文件夹
    WithPath(path string)

    // 设置读取文件
    WithFile(fileName ...string)

    SetDefault(keyName string, value any)

    Set(keyName string, value any)

    IsSet(keyName string) bool

    Get(keyName string) any

    GetString(keyName string) string

    GetBool(keyName string) bool

    GetInt(keyName string) int

    GetInt32(keyName string) int32

    GetInt64(keyName string) int64

    GetUint(keyName string) uint

    GetUint32(keyName string) uint32

    GetUint64(keyName string) uint64

    GetFloat64(keyName string) float64

    GetTime(keyName string) time.Time

    GetDuration(keyName string) time.Duration

    GetIntSlice(keyName string) []int

    GetStringSlice(keyName string) []string

    GetStringMap(keyName string) map[string]any

    GetStringMapString(keyName string) map[string]string

    GetStringMapStringSlice(keyName string) map[string][]string

    GetSizeInBytes(keyName string) uint

    OnConfigChange(f func(string))
}
