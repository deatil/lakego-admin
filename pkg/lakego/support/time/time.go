package time

import (
    "time"
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
func TimeStampToTime(timeStamp int32) time.Time {
    return time.Unix(int64(timeStamp), 0)
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
