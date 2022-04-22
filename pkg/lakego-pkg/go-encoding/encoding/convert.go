package encoding

import (
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
