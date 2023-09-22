package datebin

import (
    "time"
)

// 时间
func FromTimeTime(t time.Time, timezone ...string) Datebin {
    date := defaultDatebin.WithTime(t)

    if len(timezone) > 0 {
        date = date.SetTimezone(timezone[0])
    }

    return date
}

// 时间戳
func FromTimeUnix(second int64, nsec int64, timezone ...string) Datebin {
    return FromTimeTime(time.Unix(second, nsec), timezone...)
}

// 时间戳
func FromTimestamp(timestamp int64, timezone ...string) Datebin {
    return FromTimeUnix(timestamp, 0, timezone...)
}

// 日期时间带纳秒
func FromDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond int, timezone ...string) Datebin {
    monthData, ok := Months[month]
    if !ok {
        monthData = Months[1]
    }

    return FromTimeTime(time.Date(year, monthData, day, hour, minute, second, nanosecond, time.Local), timezone...)
}

// 日期时间带微秒
func FromDatetimeWithMicrosecond(year, month, day, hour, minute, second, microsecond int, timezone ...string) Datebin {
    return FromDatetimeWithNanosecond(year, month, day, hour, minute, second, microsecond * 1e3, timezone...)
}

// 日期时间带毫秒
func FromDatetimeWithMillisecond(year, month, day, hour, minute, second, millisecond int, timezone ...string) Datebin {
    return FromDatetimeWithNanosecond(year, month, day, hour, minute, second, millisecond * 1e6, timezone...)
}

// 日期时间
func FromDatetime(year, month, day, hour, minute, second int, timezone ...string) Datebin {
    return FromDatetimeWithNanosecond(year, month, day, hour, minute, second, 0, timezone...)
}

// 日期
func FromDate(year, month, day int, timezone ...string) Datebin {
    return FromDatetimeWithNanosecond(year, month, day, 0, 0, 0, 0, timezone...)
}

// 时间
func FromTime(hour, minute, second int, timezone ...string) Datebin {
    year, month, day := Now(timezone...).Date()

    return FromDatetimeWithNanosecond(year, month, day, hour, minute, second, 0, timezone...)
}
