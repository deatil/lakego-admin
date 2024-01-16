package time

import (
    "time"

    "github.com/deatil/go-datebin/datebin"
)

var (
    DateFormat      = "2006-01-02"
    TimeFormat      = "15:04:05"
    DateTimeFormat  = "2006-01-02 15:04:05"
    DateTime2Format = "20060102150405"
)

// 默认时区
var timezone = "Asia/Hong_Kong"

// 时间格式化
type Time struct {
    time time.Time
}

// 设置时间
func (this Time) WithTime(t time.Time) Time {
    this.time = t

    return this
}

// 输出时间
func (this Time) ToTime() time.Time {
    return this.time
}

// 添加
func (this Time) Add(t time.Duration) Time {
    this.time = this.time.Add(t)

    return this
}

// 添加字符时间
func (this Time) AddString(str string) Time {
    t, _ := time.ParseDuration(str)

    this.time = this.time.Add(t)

    return this
}

// 输出格式化
func (this Time) ToFormatString(format string) string {
    if this.time.IsZero() {
        return ""
    }

    return this.time.Format(format)
}

// 输出格式化时间
func (this Time) ToDateTimeString() string {
    if this.time.IsZero() {
        return ""
    }

    return this.time.Format(DateTimeFormat)
}

// 输出格式化时间
func (this Time) ToDateTime2String() string {
    if this.time.IsZero() {
        return ""
    }

    return this.time.Format(DateTime2Format)
}

// 输出格式化时间
func (this Time) ToDateString() string {
    if this.time.IsZero() {
        return ""
    }

    return this.time.Format(DateFormat)
}

// 输出格式化时间
func (this Time) ToTimeString() string {
    if this.time.IsZero() {
        return ""
    }

    return this.time.Format(TimeFormat)
}

// 输出格式化时间
func (this Time) ToTimestamp() int64 {
    if this.time.IsZero() {
        return 0
    }

    return this.time.Unix()
}

// 设置时区
func SetTimezone(tz string) {
    timezone = tz
}

// 来源时间
func FromTime(t time.Time) Time {
    return Time{
        t.In(timeLoc()),
    }
}

// 来源时间
func FromTimestamp(timestamp int64) Time {
    return FromTime(time.Unix(timestamp, 0))
}

// 当前时间
func Now() Time {
    return FromTime(time.Now())
}

// 解析时间
func Parse(str string) Time {
    t := datebin.Parse(str).
        WithLocation(timeLoc()).
        ToStdTime()

    return Time{
        time: t,
    }
}

// 时区
func timeLoc() *time.Location {
    loc, _ := time.LoadLocation(timezone)

    return loc
}
