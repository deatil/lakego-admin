package datebin

import (
	"time"
)

// 当前时间，单位：秒
func NowTime(timezone ...string) int64 {
	return Now(timezone...).Timestamp()
}

// 当前日期时间字符
func NowDatetimeString(timezone ...string) string {
	return Now(timezone...).ToDatetimeString()
}

// 当前日期字符
func NowDateString(timezone ...string) string {
	return Now(timezone...).ToDateString()
}

// 当前时间字符
func NowTimeString(timezone ...string) string {
	return Now(timezone...).ToTimeString()
}

// 时间戳转为 time.Time
func TimestampToTime(timestamp int64, timezone ...string) time.Time {
	return FromTimestamp(timestamp, timezone...).GetTime()
}

// 时间转换为时间戳
func TimeToTimestamp(t time.Time, timezone ...string) int64 {
	return FromStdTime(t, timezone...).Timestamp()
}

// 时间字符转为时间
func StringToTime(date string, format ...string) time.Time {
	return ParseDatetimeString(date, format...).GetTime()
}

// 时间字符转为时间戳
func StringToTimestamp(date string, format ...string) int64 {
	return ParseDatetimeString(date, format...).Timestamp()
}
