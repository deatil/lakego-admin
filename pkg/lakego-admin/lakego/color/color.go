package color

import (
    "os"
    "fmt"
	"strings"

    "github.com/fatih/color"
)

var (
    rawColor = "raw"

    // 颜色数组
    colorMap = map[string]color.Attribute{
        "red":     color.FgRed,
        "green":   color.FgGreen,
        "yellow":  color.FgYellow,
        "blue":    color.FgBlue,
        "magenta": color.FgMagenta,
        "cyan":    color.FgCyan,
        "white":   color.FgWhite,
    }
)

type (
    LogFunc = func(string, ...interface{})
)

func NewColorFunc(colorname string) LogFunc {
    return func(msg string, v ...interface{}) {
        msg = strings.Replace(msg, "\n", "", -1)
        msg = strings.TrimSpace(msg)
        if len(msg) == 0 {
            return
        }

        if colorname == rawColor {
            fmt.Fprintf(os.Stdout, msg, v...)
        } else {
            color.New(GetColor(colorname)).Fprintf(color.Output, msg, v...)
        }
    }
}

func GetColor(name string) color.Attribute {
    if v, ok := colorMap[name]; ok {
        return v
    }

    return color.FgWhite
}

func ShowMessage(colorname string, msg string, arg ...interface{}) {
    NewColorFunc(colorname)(msg, arg...)
}

// Raw ...
func Raw(msg string) {
    ShowMessage("raw", msg)
}

// Rawf ...
func Rawf(msg string, arg ...interface{}) {
    ShowMessage("raw", msg, arg...)
}

// Red ...
func Red(msg string) {
    ShowMessage("red", msg)
}

// Redf ...
func Redf(msg string, arg ...interface{}) {
    ShowMessage("red", msg, arg...)
}

// Green ...
func Green(msg string) {
    ShowMessage("green", msg)
}

// Greenf ...
func Greenf(msg string, arg ...interface{}) {
    ShowMessage("green", msg, arg...)
}

// Yellow ...
func Yellow(msg string) {
    ShowMessage("yellow", msg)
}

// Yellowf ...
func Yellowf(msg string, arg ...interface{}) {
    ShowMessage("yellow", msg, arg...)
}

// Blue ...
func Blue(msg string) {
    ShowMessage("blue", msg)
}

// Bluef ...
func Bluef(msg string, arg ...interface{}) {
    ShowMessage("blue", msg, arg...)
}

// Magenta ...
func Magenta(msg string) {
    ShowMessage("magenta", msg)
}

// Magentaf ...
func Magentaf(msg string, arg ...interface{}) {
    ShowMessage("magenta", msg, arg...)
}

// Cyan ...
func Cyan(msg string) {
    ShowMessage("cyan", msg)
}

// Cyanf ...
func Cyanf(msg string, arg ...interface{}) {
    ShowMessage("cyan", msg, arg...)
}

// White ...
func White(msg string) {
    ShowMessage("white", msg)
}

// Whitef ...
func Whitef(msg string, arg ...interface{}) {
    ShowMessage("white", msg, arg...)
}

// ======

// RedString ...
func RedString(msg string) string {
    return color.RedString(msg)
}

// RedStringf ...
func RedStringf(msg string, arg ...interface{}) string {
    return color.RedString(msg, arg...)
}

// GreenString ...
func GreenString(msg string) string {
    return color.GreenString(msg)
}

// GreenStringf ...
func GreenStringf(msg string, arg ...interface{}) string {
    return color.GreenString(msg, arg...)
}

// YellowString ...
func YellowString(msg string) string {
    return color.YellowString(msg)
}

// YellowStringf ...
func YellowStringf(msg string, arg ...interface{}) string {
    return color.YellowString(msg, arg...)
}

// BlueString ...
func BlueString(msg string) string {
    return color.BlueString(msg)
}

// BlueStringf ...
func BlueStringf(msg string, arg ...interface{}) string {
    return color.BlueString(msg, arg...)
}

// MagentaString ...
func MagentaString(msg string) string {
    return color.MagentaString(msg)
}

// MagentaStringf ...
func MagentaStringf(msg string, arg ...interface{}) string {
    return color.MagentaString(msg, arg...)
}

// CyanString ...
func CyanString(msg string) string {
    return color.CyanString(msg)
}

// CyanStringf ...
func CyanStringf(msg string, arg ...interface{}) string {
    return color.CyanString(msg, arg...)
}

// WhiteString ...
func WhiteString(msg string) string {
    return color.WhiteString(msg)
}

// WhiteStringf ...
func WhiteStringf(msg string, arg ...interface{}) string {
    return color.WhiteString(msg, arg...)
}
