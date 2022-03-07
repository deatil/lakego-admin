package time

import (
    "time"
    "bytes"
)

// go 默认时间
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

var (
    // 月份
    Months = map[int]time.Month{
        1:  time.January,
        2:  time.February,
        3:  time.March,
        4:  time.April,
        5:  time.May,
        6:  time.June,
        7:  time.July,
        8:  time.August,
        9:  time.September,
        10: time.October,
        11: time.November,
        12: time.December,
    }

    // 格式字符
    FormatStrs = map[string]string{
        "D": "Mon",
        "d": "02",
        "j": "2",
        "l": "Monday",
        "z": "__2",

        "F": "January",
        "m": "01",
        "M": "Jan",
        "n": "1",

        "Y": "2006",
        "y": "06",

        "a": "pm",
        "A": "PM",
        "g": "3",
        "h": "03",
        "H": "15",
        "i": "04",
        "s": "05",
        "u": ".000000",

        "O": "-0700",
        "P": "-07:00",
        "T": "MST",

        "c": "2006-01-02T15:04:05Z07:00",
        "r": "Mon, 02 Jan 2006 15:04:05 -0700",
    }
)

/**
 * 日期
 *
 * @create 2022-3-6
 * @author deatil
 */
type Datebin struct {
    // 时间
    time time.Time

    // 时区
    loc *time.Location

    // 错误
    Error error
}

// 设置时间
func (this Datebin) WithTime(time time.Time) Datebin {
    this.time = time

    return this
}

// 获取时间
func (this Datebin) GetTime() time.Time {
    return this.time
}

// 设置时区
func (this Datebin) WithLocation(loc *time.Location) Datebin {
    this.loc = loc

    return this
}

// 获取时区
func (this Datebin) GetLocation() *time.Location {
    return this.loc
}

// 获取时区字符
func (this Datebin) GetLocationString() string {
    return this.loc.String()
}

// 设置时区字符
func (this Datebin) WithTimezone(timezone string) Datebin {
    location, err := this.GetLocationByTimezone(timezone)
    if err == nil {
        this.WithLocation(location)
    }

    return this
}

// 重新设置时区
func (this Datebin) ReplaceTimezone(timezone string) Datebin {
    // 重设
    this = this.WithTimezone(timezone)

    // 设置时区
    this.time = this.time.In(this.loc)

    return this
}

// 获取时区
func (this Datebin) GetTimezone() string {
    name, _ := this.time.Zone()
    return name
}

// 获取距离UTC时区的偏移量，单位秒
func (this Datebin) GetOffset() int {
    _, offset := this.time.Zone()
    return offset
}

// 通过时区获取 Location 实例
func (this Datebin) GetLocationByTimezone(timezone string) (*time.Location, error) {
    return time.LoadLocation(timezone)
}

// 通过持续时长解析
func (this Datebin) ParseDuration(duration string) (time.Duration, error) {
    return time.ParseDuration(duration)
}

// 获取绝对值
func (this Datebin) GetAbsValue(value int64) int64 {
    return (value ^ value>>31) - value>>31
}

// 获取错误
func (this Datebin) GetError() error {
    return this.Error
}

// 当前
func (this Datebin) Now(timezone ...string) Datebin {
    if len(timezone) > 0 {
        this.loc, this.Error = this.GetLocationByTimezone(timezone[0])
    }

    if this.Error != nil {
        return this
    }

    this.time = time.Now().In(this.loc)
    return this
}

// UTC
func (this Datebin) UTC() Datebin {
    this.time = this.time.UTC()

    return this
}

// 格式化
func (this Datebin) Format(str string) string {
    return this.time.In(this.loc).Format(this.FormatStr(str))
}

// 格式化字符为 go 对应时间字符
func (this Datebin) FormatStr(str string) string {
    var buffer bytes.Buffer

    for i := 0; i < len(str); i++ {
        val, ok := FormatStrs[str[i:i+1]]
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

// =====

// 构造函数
func NewDatebin() Datebin {
    return Datebin{
        loc: time.Local,
    }
}

// 当前
func Now(timezone ...string) Datebin {
    return NewDatebin().Now(timezone...)
}

// 时间
func Time(t time.Time) Datebin {
    return NewDatebin().WithTime(t)
}

// 时间戳
func Unix(sec int64, nsec int64) Datebin {
    return Time(time.Unix(sec, nsec))
}

// 日期
func Date(year int, month int, day int) Datebin {
    return Time(time.Date(year, Months[month], day, 0, 0, 0, 0, time.UTC))
}

// 日期时间
func Datetime(year int, month int, day int, hour int, min int, sec int) Datebin {
    return Time(time.Date(year, Months[month], day, hour, min, sec, 0, time.UTC))
}

// 时间字符
func TimeString(str string, formatStr ...string) Datebin {
    var format = ""

    if len(formatStr) > 0 {
        format = formatStr[0]
    } else if len(formatStr) == 0 && len(str) == 19 {
        format = "Y-m-d H:i:s"
    } else if len(formatStr) == 0 && len(str) == 10 {
        format = "Y-m-d"
    } else {
        format = "Y-m-d"
    }

    date := NewDatebin()

    format = date.FormatStr(format)
    time, err := time.Parse(format, str)
    if err != nil {
        return date
    }

    date.time = time

    return date
}
