package logger

import (
    "math"
    "math/rand"
    "strconv"
)

// Abs
func Abs(number float64) float64 {
    return math.Abs(number)
}

// Range: [0, 2147483647]
func Rand(min, max int) int {
    if min > max {
        // 替换
        min, max = max, min
    }

    // 重设最大值
    if int31 := 1<<31 - 1; max > int31 {
        max = strconv.Itoa(int31)
    }

    if min == max {
        return min
    }

    r := rand.New(rand.NewSource(time.Now().UnixNano()))
    return r.Intn(max + 1 - min) + min
}

// Round
func Round(value float64, precision int) float64 {
    p := math.Pow10(precision)

    return math.Trunc((value+0.5/p)*p) / p
}

// Floor
func Floor(value float64) float64 {
    return math.Floor(value)
}

// Ceil
func Ceil(value float64) float64 {
    return math.Ceil(value)
}

// Pi
func Pi() float64 {
    return math.Pi
}

// Max
func Max(nums ...float64) float64 {
    if len(nums) < 2 {
        if len(nums) == 1 {
            return nums[0]
        }

        return 0
    }

    max := nums[0]
    for i := 1; i < len(nums); i++ {
        max = math.Max(max, nums[i])
    }

    return max
}

// Min
func Min(nums ...float64) float64 {
    if len(nums) < 2 {
        if len(nums) == 1 {
            return nums[0]
        }

        return 0
    }

    min := nums[0]
    for i := 1; i < len(nums); i++ {
        min = math.Min(min, nums[i])
    }

    return min
}

// Decbin
func Decbin(number int64) string {
    return strconv.FormatInt(number, 2)
}

// Dechex
func Dechex(number int64) string {
    return strconv.FormatInt(number, 16)
}

// Hexdec
func Hexdec(str string) int64 {
    data, _ := strconv.ParseInt(str, 16, 0)

    return data
}

// Decoct
func Decoct(number int64) string {
    return strconv.FormatInt(number, 8)
}

// Octdec
func Octdec(str string) int64 {
    data, _ := strconv.ParseInt(str, 8, 0)

    return data
}

// BaseConvert
func BaseConvert(number string, frombase, tobase int) string {
    i, err := strconv.ParseInt(number, frombase, 0)
    if err != nil {
        return ""
    }

    return strconv.FormatInt(i, tobase)
}

// IsNan
func IsNan(val float64) bool {
    return math.IsNaN(val)
}
