package datebin

import (
    "time"
)

// 构造函数
func NewDatebin() Datebin {
    return New()
}

// 当前
func Now(timezone ...string) Datebin {
    return New().Now(timezone...)
}

// 今天
func Today(timezone ...string) Datebin {
    return New().Today(timezone...)
}

// 明天
func Tomorrow(timezone ...string) Datebin {
    return New().Tomorrow(timezone...)
}

// 昨天
func Yesterday(timezone ...string) Datebin {
    return New().Yesterday(timezone...)
}

// 时间
func UseTime(t time.Time, timezone ...string) Datebin {
    date := New().WithTime(t)

    if len(timezone) > 0 {
        date = date.ReplaceTimezone(timezone[0])
    }

    return date
}

// 时间戳
func Unix(second int64, nsec int64, timezone ...string) Datebin {
    return UseTime(time.Unix(second, nsec), timezone...)
}

// 时间戳
func Timestamp(timestamp int64, timezone ...string) Datebin {
    return Unix(timestamp, 0, timezone...)
}

// 日期时间带纳秒
func DatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond int, timezone ...string) Datebin {
    monthData, ok := Months[month]
    if !ok {
        monthData = Months[1]
    }

    return UseTime(time.Date(year, monthData, day, hour, minute, second, nanosecond, time.Local), timezone...)
}

// 日期时间带微秒
func DatetimeWithMicrosecond(year, month, day, hour, minute, second, microsecond int, timezone ...string) Datebin {
    return DatetimeWithNanosecond(year, month, day, hour, minute, second, microsecond * 1e3, timezone...)
}

// 日期时间带毫秒
func DatetimeWithMillisecond(year, month, day, hour, minute, second, millisecond int, timezone ...string) Datebin {
    return DatetimeWithNanosecond(year, month, day, hour, minute, second, millisecond * 1e6, timezone...)
}

// 日期时间
func Datetime(year, month, day, hour, minute, second int, timezone ...string) Datebin {
    monthData, ok := Months[month]
    if !ok {
        monthData = Months[1]
    }

    return UseTime(time.Date(year, monthData, day, hour, minute, second, 0, time.Local), timezone...)
}

// 日期
func Date(year, month, day int, timezone ...string) Datebin {
    monthData, ok := Months[month]
    if !ok {
        monthData = Months[1]
    }

    return UseTime(time.Date(year, monthData, day, 0, 0, 0, 0, time.Local), timezone...)
}

// 时间
func Time(hour, minute, second int, timezone ...string) Datebin {
    year, month, day := Now(timezone...).Date()

    monthData, ok := Months[month]
    if !ok {
        monthData = Months[1]
    }

    return UseTime(time.Date(year, monthData, day, hour, minute, second, 0, time.Local), timezone...)
}

// 解析时间字符
func Parse(date string) Datebin {
    return New().Parse(date)
}

// 用布局字符解析时间字符
func ParseWithLayout(date string, layout string, timezone ...string) Datebin {
    return New().ParseWithLayout(date, layout, timezone...)
}

// 用格式化字符解析时间字符
func ParseWithFormat(date string, format string, timezone ...string) Datebin {
    return New().ParseWithFormat(date, format, timezone...)
}

// 时间字符
func DatetimeString(date string, format ...string) Datebin {
    if len(format) > 1 && format[1] == "u" {
        return ParseWithFormat(date, format[0])
    }

    if len(format) > 0 {
        return ParseWithLayout(date, format[0])
    }

    return Parse(date)
}

// 当前时间，单位：秒
func NowTime(timezone ...string) int64 {
    return Now(timezone...).Timestamp()
}

// 当前日期时间字符
func NowDatetimeString(timezone ...string) string {
    return Now(timezone...).ToDatetimeString()
}

// 当前日期
func NowDateString(timezone ...string) string {
    return Now(timezone...).ToDateString()
}

// 当前时间字符
func NowTimeString(timezone ...string) string {
    return Now(timezone...).ToTimeString()
}

// 时间戳转为 time.Time
func TimestampToTime(timestamp int64, timezone ...string) time.Time {
    return Timestamp(timestamp, timezone...).GetTime()
}

// 时间转换为时间戳
func TimeToTimestamp(t time.Time, timezone ...string) int64 {
    return UseTime(t, timezone...).Timestamp()
}

// 时间字符转为时间
func StringToTime(date string, format ...string) time.Time {
    return DatetimeString(date, format...).GetTime()
}

// 时间字符转为时间戳
func StringToTimestamp(date string, format ...string) int64 {
    return DatetimeString(date, format...).Timestamp()
}

