// +build windows

package color

import (
    "fmt"
    "strconv"
    "math/rand"

    "github.com/fatih/color"
)

var _ = RandomColor()

// 随机生成一个颜色
func RandomColor() string {
    return fmt.Sprintf("#%s", strconv.FormatInt(int64(rand.Intn(16777216)), 16))
}

// Yellow ...
func Yellow(msg string) string {
    return color.YellowString(msg)
}

// Yellowf ...
func Yellowf(msg string, arg interface{}) string {
    return color.YellowString(fmt.Sprintf("%s %+v\n", msg, arg))
}

// Red ...
func Red(msg string) string {
    return color.RedString(msg)
}

// Redf ...
func Redf(msg string, arg interface{}) string {
    return color.RedString(fmt.Sprintf("%s %+v\n", msg, arg))
}

// Blue ...
func Blue(msg string) string {
    return color.BlueString(msg)
}

// Bluef ...
func Bluef(msg string, arg interface{}) string {
    return color.BlueString(fmt.Sprintf("%s %+v\n", msg, arg))
}

// Green ...
func Green(msg string) string {
    return color.GreenString(msg)
}

// Greenf ...
func Greenf(msg string, arg interface{}) string {
    return color.GreenString(fmt.Sprintf("%s %+v\n", msg, arg))
}
