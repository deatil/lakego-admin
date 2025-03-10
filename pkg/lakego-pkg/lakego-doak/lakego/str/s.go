package str

import (
    "unsafe"
    "strings"
    "strconv"
    "encoding/json"
)

/**
 * 字符串类型转换
 *
 * @create 2021-8-28
 * @author deatil
 */
type S string

func NewS(b []byte) S {
    return *(*S)(unsafe.Pointer(&b))
}

func (this S) String() string {
    return string(this)
}

// 转换为[]byte
func (this S) Bytes() []byte {
    return *(*[]byte)(unsafe.Pointer(&this))
}

// 转换为bool
func (this S) Bool() (bool, error) {
    b, err := strconv.ParseBool(this.String())

    if err != nil {
        return false, err
    }

    return b, nil
}

// 转换为bool，如果出现错误则使用默认值
func (this S) DefaultBool(defaultVal bool) bool {
    b, err := this.Bool()

    if err != nil {
        return defaultVal
    }

    return b
}

// 转换为int64
func (this S) Int64() (int64, error) {
    i, err := strconv.ParseInt(this.String(), 10, 64)

    if err != nil {
        return 0, err
    }

    return i, nil
}

// 转换为int64，如果出现错误则使用默认值
func (this S) DefaultInt64(defaultVal int64) int64 {
    i, err := this.Int64()

    if err != nil {
        return defaultVal
    }

    return i
}

// 转换为int
func (this S) Int() (int, error) {
    i, err := this.Int64()

    if err != nil {
        return 0, err
    }

    return int(i), nil
}

// 转换为int，如果出现错误则使用默认值
func (this S) DefaultInt(defaultVal int) int {
    i, err := this.Int()

    if err != nil {
        return defaultVal
    }

    return i
}

// 转换为uint64
func (this S) Uint64() (uint64, error) {
    i, err := strconv.ParseUint(this.String(), 10, 64)

    if err != nil {
        return 0, err
    }

    return i, nil
}

// 转换为uint64，如果出现错误则使用默认值
func (this S) DefaultUint64(defaultVal uint64) uint64 {
    i, err := this.Uint64()

    if err != nil {
        return defaultVal
    }

    return i
}

// 转换为uint
func (this S) Uint() (uint, error) {
    i, err := this.Uint64()

    if err != nil {
        return 0, err
    }

    return uint(i), nil
}

// 转换为uint，如果出现错误则使用默认值
func (this S) DefaultUint(defaultVal uint) uint {
    i, err := this.Uint()

    if err != nil {
        return defaultVal
    }

    return uint(i)
}

// 转换为float64
func (this S) Float64() (float64, error) {
    f, err := strconv.ParseFloat(this.String(), 64)

    if err != nil {
        return 0, err
    }

    return f, nil
}

// 转换为float64，如果出现错误则使用默认值
func (this S) DefaultFloat64(defaultVal float64) float64 {
    f, err := this.Float64()

    if err != nil {
        return defaultVal
    }

    return f
}

// 转换为float32
func (this S) Float32() (float32, error) {
    f, err := this.Float64()

    if err != nil {
        return 0, err
    }

    return float32(f), nil
}

// 转换为float32，如果出现错误则使用默认值
func (this S) DefaultFloat32(defaultVal float32) float32 {
    f, err := this.Float32()

    if err != nil {
        return defaultVal
    }

    return f
}

// 转换为JSON
func (this S) ToJSON(v any) error {
    return json.Unmarshal(this.Bytes(), v)
}

// 截取
func (this S) Substr(pos, length int) string {
    runes := []rune(this.String())

    l := pos + length

    if l > len(runes) {
        l = len(runes)
    }

    return string(runes[pos:l])
}

// 获取父级目录
func (this S) GetParentDir() string {
    return this.Substr(0, strings.LastIndex(this.String(), "/"))
}
