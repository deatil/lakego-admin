package time

import (
    "fmt"
    "time"
    "strings"
)

var (
    // 纳秒
    Nanosecond = time.Nanosecond

    // 微妙
    Microsecond = time.Microsecond

    // 毫秒
    Millisecond = time.Millisecond

    // 秒
    Second = time.Second

    // 分钟
    Minute = time.Minute
)

// 时间字符转为时间
func StringToTime(date interface{}) time.Time {
    timeLayout := "2006-01-02 15:04:05"
    loc, _ := time.LoadLocation("Local")
    ret, _ := time.ParseInLocation(timeLayout, date.(string), loc)
    return ret
}

// 时间字符转为时间戳
func StringToTimestamp(date interface{}) int64 {
    return StringToTime(date).Unix()
}

// 时间戳转为 time.Time
func TimeStampToTime(timeStamp int) time.Time {
    return time.Unix(int64(timeStamp), 0)
}

// 时间转换为时间戳
func TimeToStamp(strTime string) int64 {
    t, _ := time.Parse("2006-01-02 15:04:05", strTime)

    return t.Unix()
}

// 时间戳转为时间字符
func TimeStampToDate(timeStamp int) string {
    date := time.Unix(int64(timeStamp), 0).Format("2006-01-02 15:04:05")

    return date
}

// 当前时间，单位：秒
func NowTime() int64 {
    return time.Now().Unix()
}

// 当前时间，单位：秒
func NowTimeToInt() int {
    time := NowTime()
    return int(time)
}

// 当前时间，单位：纳秒
func NowNanoTime() int64 {
    return time.Now().UnixNano()
}

// 当前时间，单位：纳秒
func NowNanoTimeToInt() int {
    return int(NowNanoTime())
}

// 获取几天前时间，单位：秒
func BeforeTime(day int) int64 {
    return time.Now().AddDate(0, 0, day).Unix()
}

// 获取几天前时间，单位：秒
func BeforeTimeToInt(day int) int {
    time := BeforeTime(day)
    return int(time)
}

// 时间格式化
func FormatTime(timeUnix time.Time, format string) string {
    formatMap := map[string]string{
        "Y": fmt.Sprintf("%d", timeUnix.Year()),
        "m": fmt.Sprintf("%d", timeUnix.Month()),
        "d": fmt.Sprintf("%d", timeUnix.Day()),

        "H": fmt.Sprintf("%d", timeUnix.Hour()),
        "i": fmt.Sprintf("%d", timeUnix.Minute()),
        "s": fmt.Sprintf("%d", timeUnix.Second()),
    }

    for k, v := range formatMap {
        format = strings.Replace(format, k, v, -1)
    }

    return format
}

// 时间戳格式化
func TimeFormat(timeStamp int, format string) string {
    now := TimeStampToTime(timeStamp)

    return FormatTime(now, format)
}

// 时间
func Date(format string, timestamp int) string {
    return TimeFormat(timestamp, format)
}

// 当前时间
func NowFormat(format string) string {
    now := time.Now()

    return FormatTime(now, format)
}

