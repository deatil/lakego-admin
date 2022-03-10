package time

import (
    "time"
)

// 当前
func Now(timezone ...string) Datebin {
    return NewDatebin().Now(timezone...)
}

// 今天
func Today(timezone ...string) Datebin {
    return NewDatebin().Today(timezone...)
}

// 明天
func Tomorrow(timezone ...string) Datebin {
    return NewDatebin().Tomorrow(timezone...)
}

// 昨天
func Yesterday(timezone ...string) Datebin {
    return NewDatebin().Yesterday(timezone...)
}

// 时间
func Time(t time.Time) Datebin {
    return NewDatebin().WithTime(t)
}

// 时间戳
func Unix(sec int64, nsec int64) Datebin {
    return Time(time.Unix(sec, nsec))
}

// 时间戳
func Timestamp(timestamp int64) Datebin {
    return Unix(timestamp, 0)
}

// 日期
func Date(year int, month int, day int, timezone ...string) Datebin {
    monthData, ok := Months[month]
    if !ok {
        monthData = Months[1]
    }

    date := Time(time.Date(year, monthData, day, 0, 0, 0, 0, time.UTC))

    if len(timezone) > 0 {
        date = date.ReplaceTimezone(timezone[0])
    }

    return date
}

// 日期时间
func Datetime(year int, month int, day int, hour int, min int, sec int, timezone ...string) Datebin {
    monthData, ok := Months[month]
    if !ok {
        monthData = Months[1]
    }

    date := Time(time.Date(year, monthData, day, hour, min, sec, 0, time.UTC))

    if len(timezone) > 0 {
        date = date.ReplaceTimezone(timezone[0])
    }

    return date
}

// 时间字符
func Parse(date string, format ...string) Datebin {
    return NewDatebin().Parse(date, format...)
}

// 时间字符
func TimeString(date string, format ...string) Datebin {
    return Parse(date, format...)
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

// 时间字符转为时间
func StringToTime(date string, format ...string) time.Time {
    return TimeString(date, format...).GetTime()
}

// 时间字符转为时间戳
func StringToTimestamp(date string, format ...string) int64 {
    return TimeString(date, format...).Timestamp()
}

// 时间戳转为 time.Time
func TimestampToTime(timestamp int64) time.Time {
    return Timestamp(timestamp).GetTime()
}

// 时间转换为时间戳
func TimeToTimestamp(t time.Time) int64 {
    return Time(t).Timestamp()
}

