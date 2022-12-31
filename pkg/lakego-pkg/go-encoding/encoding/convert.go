package encoding

import (
    "errors"
    "strconv"
)

// 十进制转二进制
func Decbin(number int64) string {
    return strconv.FormatInt(number, 2)
}

// 二进制转十进制
func Bindec(str string) int64 {
    data, _ := strconv.ParseInt(str, 2, 0)

    return data
}

// 十进制转八进制
func Decoct(number int64) string {
    return strconv.FormatInt(number, 8)
}

// 八进制转十进制
func Octdec(str string) int64 {
    data, _ := strconv.ParseInt(str, 8, 0)

    return data
}

// 十进制转十六进制
func Dechex(number int64) string {
    return strconv.FormatInt(number, 16)
}

// 十六进制转十进制
func Hexdec(str string) int64 {
    data, _ := strconv.ParseInt(str, 16, 0)

    return data
}

// 各种进制互转
// 十进制转十六进制
// BaseConvert("12312", 10, 16)
// [2- 36] 进制
func BaseConvert(number string, frombase, tobase int) string {
    i, err := strconv.ParseInt(number, frombase, 0)
    if err != nil {
        return ""
    }

    return strconv.FormatInt(i, tobase)
}

// ====================

// 给定类型数据格式化为string类型数据
// bitSize 限制长度
// ParseBool()、ParseFloat()、ParseInt()、ParseUint()。
// FormatBool()、FormatInt()、FormatUint()、FormatFloat()、
func (this Encoding) FromConvert(input any, base int, bitSize ...int) Encoding {
    newBitSize := 0
    if len(bitSize) > 0 {
        newBitSize = bitSize[0]
    }

    var number int64
    var err error

    switch input.(type) {
        case int:
            number = int64(input.(int))
        case int8:
            number = int64(input.(int8))
        case int16:
            number = int64(input.(int16))
        case int32:
            number = int64(input.(int32))
        case int64:
            number = input.(int64)
        case string:
            number, err = strconv.ParseInt(input.(string), base, newBitSize)
            if err != nil {
                this.Error = err
                return this
            }
        default:
            this.Error = errors.New("数据输入格式错误")
            return this
    }

    // 转为10进制字符
    data := strconv.FormatInt(number, 10)

    this.data = []byte(data)

    return this
}

// Hex
func FromConvert(data any, base int, bitSize ...int) Encoding {
    return defaultEncode.FromConvert(data, base, bitSize...)
}

// 二进制
func (this Encoding) FromConvertBin(data string) Encoding {
    return this.FromConvert(data, 2)
}

// 二进制
func FromConvertBin(data string) Encoding {
    return defaultEncode.FromConvertBin(data)
}

// 八进制
func (this Encoding) FromConvertOct(data string) Encoding {
    return this.FromConvert(data, 8)
}

// 八进制
func FromConvertOct(data string) Encoding {
    return defaultEncode.FromConvertOct(data)
}

// 十进制
func (this Encoding) FromConvertDec(data int64) Encoding {
    return this.FromConvert(data, 10)
}

// 十进制
func FromConvertDec(data int64) Encoding {
    return defaultEncode.FromConvertDec(data)
}

// 十进制字符
func (this Encoding) FromConvertDecString(data string) Encoding {
    return this.FromConvert(data, 10)
}

// 十进制字符
func FromConvertDecString(data string) Encoding {
    return defaultEncode.FromConvertDecString(data)
}

// 十六进制
func (this Encoding) FromConvertHex(data string) Encoding {
    return this.FromConvert(data, 16)
}

// 十六进制
func FromConvertHex(data string) Encoding {
    return defaultEncode.FromConvertHex(data)
}

// ====================

// 输出进制编码
func (this Encoding) ToConvert(base int) string {
    number, err := strconv.ParseInt(string(this.data), 10, 0)
    if err != nil {
        return ""
    }

    return strconv.FormatInt(number, base)
}

// 输出 二进制
func (this Encoding) ToConvertBin() string {
    return this.ToConvert(2)
}

// 输出 八进制
func (this Encoding) ToConvertOct() string {
    return this.ToConvert(8)
}

// 输出 十进制
func (this Encoding) ToConvertDec() int64 {
    number, err := strconv.ParseInt(string(this.data), 10, 0)
    if err != nil {
        return 0
    }

    return number
}

// 输出 十进制
func (this Encoding) ToConvertDecString() string {
    return this.ToConvert(10)
}

// 输出 十六进制
func (this Encoding) ToConvertHex() string {
    return this.ToConvert(16)
}
