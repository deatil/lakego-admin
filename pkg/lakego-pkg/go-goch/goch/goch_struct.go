package goch

import "time"

// 构造函数
func New(data any) Goch {
    return Goch{
        data,
    }
}

/**
 * 数据格式转换
 *
 * @create 2022-5-15
 * @author deatil
 */
type Goch struct {
    // 数据
    data any
}

// 设置数据
func (this Goch) WithData(data any) Goch {
    this.data = data

    return this
}

// 返回数据
func (this Goch) ToData() any {
    return this.data
}

// 布尔值
func (this Goch) ToBool() bool {
    return ToBool(this.data)
}

// 时间
func (this Goch) ToTime() time.Time {
    return ToTime(this.data)
}

// 时间带时区
func (this Goch) ToTimeInDefaultLocation(location *time.Location) time.Time {
    return ToTimeInDefaultLocation(this.data, location)
}

// time.Duration
func (this Goch) ToDuration() time.Duration {
    return ToDuration(this.data)
}

// float64
func (this Goch) ToFloat64() float64 {
    return ToFloat64(this.data)
}

// float32
func (this Goch) ToFloat32() float32 {
    return ToFloat32(this.data)
}

// int64
func (this Goch) ToInt64() int64 {
    return ToInt64(this.data)
}

// int32
func (this Goch) ToInt32() int32 {
    return ToInt32(this.data)
}

// int16
func (this Goch) ToInt16() int16 {
    return ToInt16(this.data)
}

// int8
func (this Goch) ToInt8() int8 {
    return ToInt8(this.data)
}

// int
func (this Goch) ToInt() int {
    return ToInt(this.data)
}

// uint
func (this Goch) ToUint() uint {
    return ToUint(this.data)
}

// uint64
func (this Goch) ToUint64() uint64 {
    return ToUint64(this.data)
}

// uint32
func (this Goch) ToUint32() uint32 {
    return ToUint32(this.data)
}

// uint16
func (this Goch) ToUint16() uint16 {
    return ToUint16(this.data)
}

// uint8
func (this Goch) ToUint8() uint8 {
    return ToUint8(this.data)
}

// string
func (this Goch) ToString() string {
    return ToString(this.data)
}

// map[string]string
func (this Goch) ToStringMapString() map[string]string {
    return ToStringMapString(this.data)
}

// map[string][]string
func (this Goch) ToStringMapStringSlice() map[string][]string {
    return ToStringMapStringSlice(this.data)
}

// map[string]bool
func (this Goch) ToStringMapBool() map[string]bool {
    return ToStringMapBool(this.data)
}

// map[string]int
func (this Goch) ToStringMapInt() map[string]int {
    return ToStringMapInt(this.data)
}

// map[string]int64
func (this Goch) ToStringMapInt64() map[string]int64 {
    return ToStringMapInt64(this.data)
}

// map[string]any
func (this Goch) ToStringMap(i any) map[string]any {
    return ToStringMap(this.data)
}

// []any
func (this Goch) ToSlice() []any {
    return ToSlice(this.data)
}

// []bool
func (this Goch) ToBoolSlice() []bool {
    return ToBoolSlice(this.data)
}

// []string
func (this Goch) ToStringSlice() []string {
    return ToStringSlice(this.data)
}

// []int
func (this Goch) ToIntSlice() []int {
    return ToIntSlice(this.data)
}

// []time.Duration
func (this Goch) ToDurationSlice() []time.Duration {
    return ToDurationSlice(this.data)
}

// 字符
func (this Goch) String() string {
    return this.ToString()
}
