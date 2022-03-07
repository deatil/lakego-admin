package time

import (
    "time"
)

// 时间字符转为时间
func StringToTime(date string, formatStr ...string) time.Time {
    return TimeString(date, formatStr...).GetTime()
}

// 时间字符转为时间戳
func StringToTimestamp(date string, formatStr ...string) int64 {
    return TimeString(date, formatStr...).Timestamp()
}

// 时间戳转为 time.Time
func TimeStampToTime(timeStamp int64) time.Time {
    return Unix(timeStamp, 0).GetTime()
}

// 时间转换为时间戳
func TimeToStamp(strTime string) int64 {
    return TimeString(strTime).Timestamp()
}

// 时间戳转为时间字符
func TimeStampToDate(timeStamp int64) string {
    date := Unix(timeStamp, 0).DatetimeString()

    return date
}

// 当前时间，单位：秒
func NowTime() int64 {
    return Now().Timestamp()
}

// 当前时间，单位：纳秒。转换为 int: int(time)
func NowNanoTime() int64 {
    return Now().TimestampWithNanosecond()
}

// 获取几天前时间，单位：秒
func BeforeTime(day int) int64 {
    return Now().Offset("day", day).Timestamp()
}

// 当前日期时间字符
func NowDatetimeString(timezone ...string) string {
    return Now(timezone...).DatetimeString()
}

// 当前日期
func NowDateString(timezone ...string) string {
    return Now(timezone...).DateString()
}

// 当前时间字符
func NowTimeString(timezone ...string) string {
    return Now(timezone...).TimeString()
}

