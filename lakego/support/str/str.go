package str

import (
    "encoding/json"
    "strconv"
    "unsafe"
    "strings"
)

// S 字符串类型转换
type S string

func NewWithByte(b []byte) S {
    return *(*S)(unsafe.Pointer(&b))
}

func (a S) String() string {
    return string(a)
}

// Bytes 转换为[]byte
func (a S) Bytes() []byte {
    return *(*[]byte)(unsafe.Pointer(&a))
}

// Bool 转换为bool
func (a S) Bool() (bool, error) {
    b, err := strconv.ParseBool(a.String())
    if err != nil {
        return false, err
    }
    return b, nil
}

// DefaultBool 转换为bool，如果出现错误则使用默认值
func (a S) DefaultBool(defaultVal bool) bool {
    b, err := a.Bool()
    if err != nil {
        return defaultVal
    }
    return b
}

// Int64 转换为int64
func (a S) Int64() (int64, error) {
    i, err := strconv.ParseInt(a.String(), 10, 64)
    if err != nil {
        return 0, err
    }
    return i, nil
}

// DefaultInt64 转换为int64，如果出现错误则使用默认值
func (a S) DefaultInt64(defaultVal int64) int64 {
    i, err := a.Int64()
    if err != nil {
        return defaultVal
    }
    return i
}

// Int 转换为int
func (a S) Int() (int, error) {
    i, err := a.Int64()
    if err != nil {
        return 0, err
    }
    return int(i), nil
}

// DefaultInt 转换为int，如果出现错误则使用默认值
func (a S) DefaultInt(defaultVal int) int {
    i, err := a.Int()
    if err != nil {
        return defaultVal
    }
    return i
}

// Uint64 转换为uint64
func (a S) Uint64() (uint64, error) {
    i, err := strconv.ParseUint(a.String(), 10, 64)
    if err != nil {
        return 0, err
    }
    return i, nil
}

// DefaultUint64 转换为uint64，如果出现错误则使用默认值
func (a S) DefaultUint64(defaultVal uint64) uint64 {
    i, err := a.Uint64()
    if err != nil {
        return defaultVal
    }
    return i
}

// Uint 转换为uint
func (a S) Uint() (uint, error) {
    i, err := a.Uint64()
    if err != nil {
        return 0, err
    }
    return uint(i), nil
}

// DefaultUint 转换为uint，如果出现错误则使用默认值
func (a S) DefaultUint(defaultVal uint) uint {
    i, err := a.Uint()
    if err != nil {
        return defaultVal
    }
    return uint(i)
}

// Float64 转换为float64
func (a S) Float64() (float64, error) {
    f, err := strconv.ParseFloat(a.String(), 64)
    if err != nil {
        return 0, err
    }
    return f, nil
}

// DefaultFloat64 转换为float64，如果出现错误则使用默认值
func (a S) DefaultFloat64(defaultVal float64) float64 {
    f, err := a.Float64()
    if err != nil {
        return defaultVal
    }
    return f
}

// Float32 转换为float32
func (a S) Float32() (float32, error) {
    f, err := a.Float64()
    if err != nil {
        return 0, err
    }
    return float32(f), nil
}

// DefaultFloat32 转换为float32，如果出现错误则使用默认值
func (a S) DefaultFloat32(defaultVal float32) float32 {
    f, err := a.Float32()
    if err != nil {
        return defaultVal
    }
    return f
}

// ToJSON 转换为JSON
func (a S) ToJSON(v interface{}) error {
    return json.Unmarshal(a.Bytes(), v)
}

// 截取
func Substr(s string, pos, length int) string {
    runes := []rune(s)
    l := pos + length
    if l > len(runes) {
        l = len(runes)
    }
    
    return string(runes[pos:l])
}

// 获取父级目录
func GetParentDir(dir string) string {
    return Substr(dir, 0, strings.LastIndex(dir, "/"))
}
