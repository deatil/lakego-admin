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
        "black":   color.FgBlack,
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
    ColorFunc = func(string, ...interface{})
)

func NewColorFunc(colorname string) ColorFunc {
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

func Raw(msg string, arg ...interface{}) {
    ShowMessage("raw", msg, arg...)
}

// ======

func Black(msg string, arg ...interface{}) {
    ShowMessage("black", msg, arg...)
}

func Red(msg string, arg ...interface{}) {
    ShowMessage("red", msg, arg...)
}

func Green(msg string, arg ...interface{}) {
    ShowMessage("green", msg, arg...)
}

func Yellow(msg string, arg ...interface{}) {
    ShowMessage("yellow", msg, arg...)
}

func Blue(msg string, arg ...interface{}) {
    ShowMessage("blue", msg, arg...)
}

func Magenta(msg string, arg ...interface{}) {
    ShowMessage("magenta", msg, arg...)
}

func Cyan(msg string, arg ...interface{}) {
    ShowMessage("cyan", msg, arg...)
}

func White(msg string, arg ...interface{}) {
    ShowMessage("white", msg, arg...)
}

// ======

func BlackPrint(msg string, a ...interface{}) {
    color.Black(msg, a...)
}

func RedPrint(msg string, a ...interface{}) {
    color.Red(msg, a...)
}

func GreenPrint(msg string, a ...interface{}) {
    color.Green(msg, a...)
}

func YellowPrint(msg string, a ...interface{}) {
    color.Yellow(msg, a...)
}

func BluePrint(msg string, a ...interface{}) {
    color.Blue(msg, a...)
}

func MagentaPrint(msg string, a ...interface{}) {
    color.Magenta(msg, a...)
}

func CyanPrint(msg string, a ...interface{}) {
    color.Cyan(msg, a...)
}

func WhitePrint(msg string, a ...interface{}) {
    color.White(msg, a...)
}

// ======

func BlackString(msg string, a ...interface{}) string {
    return color.BlackString(msg, a...)
}

func RedString(msg string, a ...interface{}) string {
    return color.RedString(msg, a...)
}

func GreenString(msg string, a ...interface{}) string {
    return color.GreenString(msg, a...)
}

func YellowString(msg string, a ...interface{}) string {
    return color.YellowString(msg, a...)
}

func BlueString(msg string, a ...interface{}) string {
    return color.BlueString(msg, a...)
}

func MagentaString(msg string, a ...interface{}) string {
    return color.MagentaString(msg, a...)
}

func CyanString(msg string, a ...interface{}) string {
    return color.CyanString(msg, a...)
}

func WhiteString(msg string, a ...interface{}) string {
    return color.WhiteString(msg, a...)
}

// ======

func HiBlack(format string, a ...interface{}) {
    color.HiBlack(format, a...)
}

func HiRed(format string, a ...interface{}) {
    color.HiRed(format, a...)
}

func HiGreen(format string, a ...interface{}) {
    color.HiGreen(format, a...)
}

func HiYellow(format string, a ...interface{}) {
    color.HiYellow(format, a...)
}

func HiBlue(format string, a ...interface{}) {
    color.HiBlue(format, a...)
}

func HiMagenta(format string, a ...interface{}) {
    color.HiMagenta(format, a...)
}

func HiCyan(format string, a ...interface{}) {
    color.HiCyan(format, a...)
}

func HiWhite(format string, a ...interface{}) {
    color.HiWhite(format, a...)
}

// ======

func HiBlackString(format string, a ...interface{}) string {
    return color.HiBlackString(format, a...)
}

func HiRedString(format string, a ...interface{}) string {
    return color.HiRedString(format, a...)
}

func HiGreenString(format string, a ...interface{}) string {
    return color.HiGreenString(format, a...)
}

func HiYellowString(format string, a ...interface{}) string {
    return color.HiYellowString(format, a...)
}

func HiBlueString(format string, a ...interface{}) string {
    return color.HiBlueString(format, a...)
}

func HiMagentaString(format string, a ...interface{}) string {
    return color.HiMagentaString(format, a...)
}

func HiCyanString(format string, a ...interface{}) string {
    return color.HiCyanString(format, a...)
}

func HiWhiteString(format string, a ...interface{}) string {
    return color.HiWhiteString(format, a...)
}
