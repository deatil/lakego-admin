// +build linux

package color

import (
    "fmt"
    "math/rand"
    "strconv"
)

var _ = RandomColor()

// 随机生成一个颜色
func RandomColor() string {
    return fmt.Sprintf("#%s", strconv.FormatInt(int64(rand.Intn(16777216)), 16))
}

// Yellow ...
func Yellow(msg string) string {
    return fmt.Sprintf("\x1b[33m%s\x1b[0m", msg)
}

// Yellowf ...
func Yellowf(msg string) string {
    return fmt.Sprintf("\x1b[33m%s\x1b[0m %+v", msg, arg)
}

// Red ...
func Red(msg string) string {
    return fmt.Sprintf("\x1b[31m%s\x1b[0m", msg)
}

// Redf ...
func Redf(msg string, arg interface{}) string {
    return fmt.Sprintf("\x1b[31m%s\x1b[0m %+v\n", msg, arg)
}

// Blue ...
func Blue(msg string) string {
    return fmt.Sprintf("\x1b[34m%s\x1b[0m", msg)
}

// Bluef ...
func Bluef(msg string) string {
    return fmt.Sprintf("\x1b[34m%s\x1b[0m %+v", msg, arg)
}

// Green ...
func Green(msg string) string {
    return fmt.Sprintf("\x1b[32m%s\x1b[0m", msg)
}

// Greenf ...
func Greenf(msg string, arg interface{}) string {
    return fmt.Sprintf("\x1b[32m%s\x1b[0m %+v\n", msg, arg)
}
