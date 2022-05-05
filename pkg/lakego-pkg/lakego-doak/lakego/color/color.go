package color

import (
    "os"
    "fmt"
    "strings"

    "github.com/fatih/color"
)

var (
    // NoColor defines if the output is colorized or not.
    NoColor = color.NoColor

    // Output defines the standard output of the print functions. By default
    // os.Stdout is used.
    Output = color.Output

    // Error defines a color supporting writer for os.Stderr.
    Error = color.Error

    // 基础样式
    baseMap = map[string]color.Attribute{
        "reset":         color.Reset,
        "bold":          color.Bold,
        "faint":         color.Faint,
        "italic":        color.Italic,
        "underline":     color.Underline,
        "blinkSlow":     color.BlinkSlow,
        "blinkRapid":    color.BlinkRapid,
        "reverseVideo":  color.ReverseVideo,
        "concealed":     color.Concealed,
        "crossedOut":    color.CrossedOut,
    }

    // 前景色
    foregroundMap = map[string]color.Attribute{
        "black":   color.FgBlack,
        "red":     color.FgRed,
        "green":   color.FgGreen,
        "yellow":  color.FgYellow,
        "blue":    color.FgBlue,
        "magenta": color.FgMagenta,
        "cyan":    color.FgCyan,
        "white":   color.FgWhite,
    }

    // 前景高亮色
    foregroundHiMap = map[string]color.Attribute{
        "black":   color.FgHiBlack,
        "red":     color.FgHiRed,
        "green":   color.FgHiGreen,
        "yellow":  color.FgHiYellow,
        "blue":    color.FgHiBlue,
        "magenta": color.FgHiMagenta,
        "cyan":    color.FgHiCyan,
        "white":   color.FgHiWhite,
    }

    // 背景色
    backgroundMap = map[string]color.Attribute{
        "black":   color.BgBlack,
        "red":     color.BgRed,
        "green":   color.BgGreen,
        "yellow":  color.BgYellow,
        "blue":    color.BgBlue,
        "magenta": color.BgMagenta,
        "cyan":    color.BgCyan,
        "white":   color.BgWhite,
    }

    // 背景高亮色
    backgroundHiMap = map[string]color.Attribute{
        "black":   color.BgHiBlack,
        "red":     color.BgHiRed,
        "green":   color.BgHiGreen,
        "yellow":  color.BgHiYellow,
        "blue":    color.BgHiBlue,
        "magenta": color.BgHiMagenta,
        "cyan":    color.BgHiCyan,
        "white":   color.BgHiWhite,
    }

    // 原始颜色
    rawColor = "raw"
)

type (
    ColorFunc = func(string, ...any)
)

// 根据选项显示颜色
func New(value ...color.Attribute) *color.Color {
    return NewWithOption(value...)
}

// 根据选项显示颜色
func NewWithOption(value ...color.Attribute) *color.Color {
    return color.New(value...)
}

// 实例化一个方法
func NewColorFunc(colorname string) ColorFunc {
    return func(msg string, v ...any) {
        if len(msg) == 0 {
            return
        }

        if colorname == rawColor {
            fmt.Fprintf(os.Stdout, msg, v...)
        } else {
            NewWithOption(ForegroundOption(colorname)).
                Fprintf(color.Output, msg, v...)
        }
    }
}

// 清除多余字符
func FormatTrim(msg string) string {
    msg = strings.Replace(msg, "\n", "", -1)
    msg = strings.TrimSpace(msg)

    return msg
}

// ======

// 基础设置，可用参数
// reset | bold | faint | italic | underline
// blinkSlow | blinkRapid | reverseVideo | concealed | crossedOut
func BaseOption(name string) color.Attribute {
    if v, ok := baseMap[name]; ok {
        return v
    }

    return color.Reset
}

// 前景色，可用颜色
// black | red | green | yellow | blue | magenta | cyan | white
func ForegroundOption(name string) color.Attribute {
    if v, ok := foregroundMap[name]; ok {
        return v
    }

    return color.FgWhite
}

// 前景高亮色，可用颜色
// black | red | green | yellow | blue | magenta | cyan | white
func ForegroundHiOption(name string) color.Attribute {
    if v, ok := foregroundHiMap[name]; ok {
        return v
    }

    return color.FgHiWhite
}

// 背景色，可用颜色
// black | red | green | yellow | blue | magenta | cyan | white
func BackgroundOption(name string) color.Attribute {
    if v, ok := backgroundMap[name]; ok {
        return v
    }

    return color.BgWhite
}

// 背景高亮色，可用颜色
// black | red | green | yellow | blue | magenta | cyan | white
func BackgroundHiOption(name string) color.Attribute {
    if v, ok := backgroundHiMap[name]; ok {
        return v
    }

    return color.BgHiWhite
}

// ======

func ShowMessage(colorname string, msg string, arg ...any) {
    NewColorFunc(colorname)(msg, arg...)
}

func ShowMessageln(colorname string, msg string, arg ...any) {
    msg = msg + "\n"
    ShowMessage(colorname, msg, arg...)
}

func Raw(msg string, arg ...any) {
    ShowMessage("raw", msg, arg...)
}

func Rawln(msg string, arg ...any) {
    ShowMessageln("raw", msg, arg...)
}

// ======

func Black(msg string, arg ...any) {
    ShowMessage("black", msg, arg...)
}

func Red(msg string, arg ...any) {
    ShowMessage("red", msg, arg...)
}

func Green(msg string, arg ...any) {
    ShowMessage("green", msg, arg...)
}

func Yellow(msg string, arg ...any) {
    ShowMessage("yellow", msg, arg...)
}

func Blue(msg string, arg ...any) {
    ShowMessage("blue", msg, arg...)
}

func Magenta(msg string, arg ...any) {
    ShowMessage("magenta", msg, arg...)
}

func Cyan(msg string, arg ...any) {
    ShowMessage("cyan", msg, arg...)
}

func White(msg string, arg ...any) {
    ShowMessage("white", msg, arg...)
}


// ======

func Blackln(msg string, arg ...any) {
    ShowMessageln("black", msg, arg...)
}

func Redln(msg string, arg ...any) {
    ShowMessageln("red", msg, arg...)
}

func Greenln(msg string, arg ...any) {
    ShowMessageln("green", msg, arg...)
}

func Yellowln(msg string, arg ...any) {
    ShowMessageln("yellow", msg, arg...)
}

func Blueln(msg string, arg ...any) {
    ShowMessageln("blue", msg, arg...)
}

func Magentaln(msg string, arg ...any) {
    ShowMessageln("magenta", msg, arg...)
}

func Cyanln(msg string, arg ...any) {
    ShowMessageln("cyan", msg, arg...)
}

func Whiteln(msg string, arg ...any) {
    ShowMessageln("white", msg, arg...)
}

// ======

func BlackPrint(msg string, arg ...any) {
    color.Black(msg, arg...)
}

func RedPrint(msg string, arg ...any) {
    color.Red(msg, arg...)
}

func GreenPrint(msg string, arg ...any) {
    color.Green(msg, arg...)
}

func YellowPrint(msg string, arg ...any) {
    color.Yellow(msg, arg...)
}

func BluePrint(msg string, arg ...any) {
    color.Blue(msg, arg...)
}

func MagentaPrint(msg string, arg ...any) {
    color.Magenta(msg, arg...)
}

func CyanPrint(msg string, arg ...any) {
    color.Cyan(msg, arg...)
}

func WhitePrint(msg string, arg ...any) {
    color.White(msg, arg...)
}

// ======

func BlackString(msg string, arg ...any) string {
    return color.BlackString(msg, arg...)
}

func RedString(msg string, arg ...any) string {
    return color.RedString(msg, arg...)
}

func GreenString(msg string, arg ...any) string {
    return color.GreenString(msg, arg...)
}

func YellowString(msg string, arg ...any) string {
    return color.YellowString(msg, arg...)
}

func BlueString(msg string, arg ...any) string {
    return color.BlueString(msg, arg...)
}

func MagentaString(msg string, arg ...any) string {
    return color.MagentaString(msg, arg...)
}

func CyanString(msg string, arg ...any) string {
    return color.CyanString(msg, arg...)
}

func WhiteString(msg string, arg ...any) string {
    return color.WhiteString(msg, arg...)
}

// ======

func HiBlack(format string, arg ...any) {
    color.HiBlack(format, arg...)
}

func HiRed(format string, arg ...any) {
    color.HiRed(format, arg...)
}

func HiGreen(format string, arg ...any) {
    color.HiGreen(format, arg...)
}

func HiYellow(format string, arg ...any) {
    color.HiYellow(format, arg...)
}

func HiBlue(format string, arg ...any) {
    color.HiBlue(format, arg...)
}

func HiMagenta(format string, arg ...any) {
    color.HiMagenta(format, arg...)
}

func HiCyan(format string, arg ...any) {
    color.HiCyan(format, arg...)
}

func HiWhite(format string, arg ...any) {
    color.HiWhite(format, arg...)
}

// ======

func HiBlackString(format string, arg ...any) string {
    return color.HiBlackString(format, arg...)
}

func HiRedString(format string, arg ...any) string {
    return color.HiRedString(format, arg...)
}

func HiGreenString(format string, arg ...any) string {
    return color.HiGreenString(format, arg...)
}

func HiYellowString(format string, arg ...any) string {
    return color.HiYellowString(format, arg...)
}

func HiBlueString(format string, arg ...any) string {
    return color.HiBlueString(format, arg...)
}

func HiMagentaString(format string, arg ...any) string {
    return color.HiMagentaString(format, arg...)
}

func HiCyanString(format string, arg ...any) string {
    return color.HiCyanString(format, arg...)
}

func HiWhiteString(format string, arg ...any) string {
    return color.HiWhiteString(format, arg...)
}
