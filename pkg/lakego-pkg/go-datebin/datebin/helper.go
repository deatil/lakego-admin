package datebin

import (
	"time"
)

// 当前时间戳
// get now time Timestamp
func NowTimestamp(timezone ...string) int64 {
	return Now(timezone...).Timestamp()
}

// 当前日期时间字符
// get now time Datetime string
func NowDatetimeString(timezone ...string) string {
	return Now(timezone...).ToDatetimeString()
}

// 当前日期字符
// get now time Date string
func NowDateString(timezone ...string) string {
	return Now(timezone...).ToDateString()
}

// 当前时间字符
// get now time Time string
func NowTimeString(timezone ...string) string {
	return Now(timezone...).ToTimeString()
}

// 时间戳转为标准时间
// timestamp to std time
func TimestampToStdTime(timestamp int64, timezone ...string) time.Time {
	return FromTimestamp(timestamp, timezone...).GetTime()
}

// 标准时间转换为时间戳
// std time to timestamp
func StdTimeToTimestamp(t time.Time, timezone ...string) int64 {
	return FromStdTime(t, timezone...).Timestamp()
}

// 时间字符转为标准时间
// date string to std time
func StringToStdTime(date string, format ...string) time.Time {
	return ParseDatetimeString(date, format...).GetTime()
}

// 时间字符转为时间戳
// date string to timestamp
func StringToTimestamp(date string, format ...string) int64 {
	return ParseDatetimeString(date, format...).Timestamp()
}
