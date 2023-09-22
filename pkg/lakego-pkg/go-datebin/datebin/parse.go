package datebin

import (
    "time"
    "bytes"
    "strconv"
    "strings"
)

// 解析时间字符
func (this Datebin) Parse(date string) Datebin {
    // 解析需要的格式
    var layout = DatetimeFormat

    if _, err := strconv.ParseInt(date, 10, 64); err == nil {
        switch {
            case len(date) == 8:
                layout = ShortDateFormat
            case len(date) == 14:
                layout = ShortDatetimeFormat
        }
    } else {
        switch {
            case len(date) == 10 && strings.Count(date, "-") == 2:
                layout = DateFormat
            case len(date) == 19 && strings.Count(date, "-") == 2 && strings.Count(date, ":") == 2:
                layout = DatetimeFormat
            case len(date) == 18 && strings.Index(date, ".") == 14:
                layout = ShortDatetimeMilliFormat
            case len(date) == 21 && strings.Index(date, ".") == 14:
                layout = ShortDatetimeMicroFormat
            case len(date) == 24 && strings.Index(date, ".") == 14:
                layout = ShortDatetimeNanoFormat
            case len(date) == 25 && strings.Index(date, "T") == 10:
                layout = RFC3339Format
            case len(date) == 29 && strings.Index(date, "T") == 10 && strings.Index(date, ".") == 19:
                layout = RFC3339MilliFormat
            case len(date) == 32 && strings.Index(date, "T") == 10 && strings.Index(date, ".") == 19:
                layout = RFC3339MicroFormat
            case len(date) == 35 && strings.Index(date, "T") == 10 && strings.Index(date, ".") == 19:
                layout = RFC3339NanoFormat
        }
    }

    time, err := time.Parse(layout, date)
    if err != nil {
        return this.AppendError(err)
    }

    this.time = time

    return this
}

// 解析时间字符
func Parse(date string) Datebin {
    return defaultDatebin.Parse(date)
}

// 用布局字符解析时间字符
func (this Datebin) ParseWithLayout(date string, layout string, timezone ...string) Datebin {
    if len(timezone) > 0 {
        this = this.WithTimezone(timezone[0])
    }

    time, err := time.ParseInLocation(layout, date, this.loc)
    if err != nil {
        return this.AppendError(err)
    }

    this.time = time

    return this
}

// 用布局字符解析时间字符
func ParseWithLayout(date string, layout string, timezone ...string) Datebin {
    return defaultDatebin.ParseWithLayout(date, layout, timezone...)
}

// 用格式化字符解析时间字符
func (this Datebin) ParseWithFormat(date string, format string, timezone ...string) Datebin {
    return this.ParseWithLayout(date, this.formatParseLayout(format), timezone...)
}

// 用格式化字符解析时间字符
func ParseWithFormat(date string, format string, timezone ...string) Datebin {
    return defaultDatebin.ParseWithFormat(date, format, timezone...)
}

// 时间字符
func ParseDatetimeString(date string, format ...string) Datebin {
    if len(format) > 1 && format[1] == "u" {
        return ParseWithFormat(date, format[0])
    }

    if len(format) > 0 {
        return ParseWithLayout(date, format[0])
    }

    return Parse(date)
}

// 格式化解析 layout
func (this Datebin) formatParseLayout(str string) string {
    var buffer bytes.Buffer

    for i := 0; i < len(str); i++ {
        val, ok := PaseFormats[str[i:i+1]]
        if ok {
            buffer.WriteString(val)
        } else {
            switch str[i] {
                case '\\':
                    buffer.WriteByte(str[i+1])
                    i++
                    continue
                default:
                    buffer.WriteByte(str[i])
            }
        }
    }

    return buffer.String()
}
