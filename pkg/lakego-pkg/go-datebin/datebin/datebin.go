package datebin

import (
    "time"
)

var (
    // 解析的格式字符
    PaseFormats = map[string]string{
        "D": "Mon",
        "d": "02",
        "N": "Monday",
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
        "G": "=G=15",
        "h": "03",
        "H": "15",
        "i": "04",
        "s": "05",
        "u": "000000",

        "O": "-0700",
        "P": "-07:00",
        "T": "MST",

        "c": "2006-01-02T15:04:05Z07:00",
        "r": "Mon, 02 Jan 2006 15:04:05 -0700",
    }

    // 输出的格式字符
    ToFormats = map[string]string{
        "D": "Mon",
        "d": "02",
        "j": "2",
        "l": "Monday",

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

        "O": "-0700",
        "P": "-07:00",
        "T": "MST",

        "c": "2006-01-02T15:04:05Z07:00",
        "r": "Mon, 02 Jan 2006 15:04:05 -0700",
    }

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

    // 周列表
    Weekdays = []string{
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
    }
)

// 默认
var defaultDatebin = NewDatebin()

/**
 * 日期
 *
 * @create 2022-3-6
 * @author deatil
 */
type Datebin struct {
    // 时间
    time time.Time

    // 周开始
    weekStartAt time.Weekday

    // 时区
    loc *time.Location

    // 错误
    Errors []error
}

// 构造函数
func NewDatebin() Datebin {
    return Datebin{
        loc:         time.Local,
        weekStartAt: time.Monday,
    }
}

// 构造函数
func New() Datebin {
    return NewDatebin()
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

// 设置周开始时间
func (this Datebin) WithWeekStartAt(weekday time.Weekday) Datebin {
    this.weekStartAt = weekday
    return this
}

// 获取周开始时间
func (this Datebin) GetWeekStartAt() time.Weekday {
    return this.weekStartAt
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

// 设置时区
func (this Datebin) WithTimezone(timezone string) Datebin {
    loc, err := this.GetLocationByTimezone(timezone)
    if err != nil {
        return this.AppendError(err)
    }

    this.loc = loc

    return this
}

// 设置时区, 直接更改
func (this Datebin) SetTimezone(timezone string) Datebin {
    date := this.WithTimezone(timezone)

    // 设置时区
    date.time = date.time.In(date.loc)

    return date
}

// 全局设置时区
func SetTimezone(timezone string) {
    defaultDatebin = defaultDatebin.SetTimezone(timezone)
}

// 获取时区 Zone 名称
func (this Datebin) GetTimezone() string {
    name, _ := this.time.Zone()
    return name
}

// 获取距离UTC时区的偏移量，单位秒
func (this Datebin) GetOffset() int {
    _, offset := this.time.Zone()
    return offset
}

// 获取错误信息
func (this Datebin) GetErrors() []error {
    return this.Errors
}

// 使用设置的时区
func (this Datebin) NewTime() Datebin {
    this.time = this.time.In(this.loc)

    return this
}
