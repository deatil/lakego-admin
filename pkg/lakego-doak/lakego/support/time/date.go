package time

import (
    "time"
    "bytes"
    "strings"
)

// 时区常量
const (
    Local = "Local"
    CET   = "CET"
    EET   = "EET"
    EST   = "EST"
    GMT   = "GMT"
    UTC   = "UTC"
    UCT   = "UCT"
    MST   = "MST"

    Cuba      = "Cuba"      // 古巴
    Egypt     = "Egypt"     // 埃及
    Eire      = "Eire"      // 爱尔兰
    Greenwich = "Greenwich" // 格林尼治
    Iceland   = "Iceland"   // 冰岛
    Iran      = "Iran"      // 伊朗
    Israel    = "Israel"    // 以色列
    Jamaica   = "Jamaica"   // 牙买加
    Japan     = "Japan"     // 日本
    Libya     = "Libya"     // 利比亚
    Poland    = "Poland"    // 波兰
    Portugal  = "Portugal"  // 葡萄牙
    PRC       = "PRC"       // 中国
    Singapore = "Singapore" // 新加坡
    Turkey    = "Turkey"    // 土耳其

    Shanghai   = "Asia/Shanghai"       // 上海
    Chongqing  = "Asia/Chongqing"      // 重庆
    Harbin     = "Asia/Harbin"         // 哈尔滨
    HongKong   = "Asia/Hong_Kong"      // 香港
    Macao      = "Asia/Macao"          // 澳门
    Taipei     = "Asia/Taipei"         // 台北
    Tokyo      = "Asia/Tokyo"          // 东京
    Saigon     = "Asia/Saigon"         // 西贡
    Seoul      = "Asia/Seoul"          // 首尔
    Bangkok    = "Asia/Bangkok"        // 曼谷
    Dubai      = "Asia/Dubai"          // 迪拜
    NewYork    = "America/New_York"    // 纽约
    LosAngeles = "America/Los_Angeles" // 洛杉矶
    Chicago    = "America/Chicago"     // 芝加哥
    Moscow     = "Europe/Moscow"       // 莫斯科
    London     = "Europe/London"       // 伦敦
    Berlin     = "Europe/Berlin"       // 柏林
    Paris      = "Europe/Paris"        // 巴黎
    Rome       = "Europe/Rome"         // 罗马
)

// 月份常量
const (
    January   = "January"   // 一月
    February  = "February"  // 二月
    March     = "March"     // 三月
    April     = "April"     // 四月
    May       = "May"       // 五月
    June      = "June"      // 六月
    July      = "July"      // 七月
    August    = "August"    // 八月
    September = "September" // 九月
    October   = "October"   // 十月
    November  = "November"  // 十一月
    December  = "December"  // 十二月
)

// 星期常量
const (
    Monday    = "Monday"    // 周一
    Tuesday   = "Tuesday"   // 周二
    Wednesday = "Wednesday" // 周三
    Thursday  = "Thursday"  // 周四
    Friday    = "Friday"    // 周五
    Saturday  = "Saturday"  // 周六
    Sunday    = "Sunday"    // 周日
)

// 数字常量
const (
    YearsPerMillennium         = 1000    // 每千年1000年
    YearsPerCentury            = 100     // 每世纪100年
    YearsPerDecade             = 10      // 每十年10年
    QuartersPerYear            = 4       // 每年4季度
    MonthsPerYear              = 12      // 每年12月
    MonthsPerQuarter           = 3       // 每季度3月
    WeeksPerNormalYear         = 52      // 每常规年52周
    weeksPerLongYear           = 53      // 每长年53周
    WeeksPerMonth              = 4       // 每月4周
    DaysPerLeapYear            = 366     // 每闰年366天
    DaysPerNormalYear          = 365     // 每常规年365天
    DaysPerWeek                = 7       // 每周7天
    HoursPerWeek               = 168     // 每周168小时
    HoursPerDay                = 24      // 每天24小时
    MinutesPerDay              = 1440    // 每天1440分钟
    MinutesPerHour             = 60      // 每小时60分钟
    SecondsPerWeek             = 604800  // 每周604800秒
    SecondsPerDay              = 86400   // 每天86400秒
    SecondsPerHour             = 3600    // 每小时3600秒
    SecondsPerMinute           = 60      // 每分钟60秒
    MillisecondsPerSecond      = 1000    // 每秒1000毫秒
    MicrosecondsPerMillisecond = 1000    // 每毫秒1000微秒
    MicrosecondsPerSecond      = 1000000 // 每秒1000000微秒
)

// 时间格式化常量
const (
    AnsicFormat         = time.ANSIC
    UnixDateFormat      = time.UnixDate
    RubyDateFormat      = time.RubyDate
    RFC822Format        = time.RFC822
    RFC822ZFormat       = time.RFC822Z
    RFC850Format        = time.RFC850
    RFC1123Format       = time.RFC1123
    RFC1123ZFormat      = time.RFC1123Z
    RssFormat           = time.RFC1123Z
    RFC2822Format       = time.RFC1123Z
    RFC3339Format       = time.RFC3339
    KitchenFormat       = time.Kitchen
    CookieFormat        = "Monday, 02-Jan-2006 15:04:05 MST"
    ISO8601Format       = "2006-01-02T15:04:05-07:00"
    RFC1036Format       = "Mon, 02 Jan 06 15:04:05 -0700"
    RFC7231Format       = "Mon, 02 Jan 2006 15:04:05 GMT"
    DayDateTimeFormat   = "Mon, Jan 2, 2006 3:04 PM"
    DateTimeFormat      = "2006-01-02 15:04:05"
    DateFormat          = "2006-01-02"
    TimeFormat          = "15:04:05"
    ShortDateTimeFormat = "20060102150405"
    ShortDateFormat     = "20060102"
    ShortTimeFormat     = "150405"
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

    // 周列表
    Weeks = []string{
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
    }

    // 格式化字符
    FormatDatetimeStr = "2006-01-02 15:04:05"
    FormatDateStr = "2006-01-02"
    FormatTimeStr = "15:04:05"
)

/**
 * 日期
 *
 * @create 2022-3-6
 * @author deatil
 */
type Date struct {
    time.Time
}

// 是否是零值时间
func (this Date) IsZero() bool {
    return this.Time.IsZero()
}

// 是否是无效时间
func (this Date) IsInvalid() bool {
    if this.IsZero() {
        return true
    }

    return false
}

// 间隔
func (this Date) Offset(field string, offset int) Date {
    field = strings.ToLower(field)

    switch field {
        case "year":
            this.Time = this.Time.AddDate(offset, 0, 0)
        case "month":
            this.Time = this.Time.AddDate(0, offset, 0)
        case "day":
            this.Time = this.Time.AddDate(0, 0, offset)
        case "hour":
            this.Time = this.Time.Add(time.Hour * time.Duration(offset))
        case "minute":
            this.Time = this.Time.Add(time.Minute * time.Duration(offset))
        case "second":
            this.Time = this.Time.Add(time.Second * time.Duration(offset))
        default:
    }

    return this
}

// 通过时区获取 Location 实例
func GetLocationByTimezone(timezone string) (*time.Location, error) {
    return time.LoadLocation(timezone)
}

// 设置时区
func (this Date) Location(timezone string) Date {
    location, err := GetLocationByTimezone(timezone)
    if err != nil {
        location, _ = time.LoadLocation("Local")
    }

    this.Time = this.Time.In(location)

    return this
}

// UTC
func (this Date) UTC() Date {
    this.Time = this.Time.UTC()

    return this
}

// 日期时间
func (this Date) DatetimeStr() string {
    return this.Format(FormatDatetimeStr)
}

// 日期
func (this Date) DateStr() string {
    return this.Format(FormatDateStr)
}

// 时间
func (this Date) TimeStr() string {
    return this.Format(FormatTimeStr)
}

// 一天时间开始字符 2006-01-02 00:00:00
func (this Date) DayBeginDateTimeStr() string {
    return this.Format(FormatDateStr) + " 00:00:00"
}

// 一天时间结束字符 2006-01-02 23:59:59
func (this Date) DayEndDateTimeStr() string {
    return this.Format(FormatDateStr) + " 23:59:59"
}

// millisecond
func (this Date) UnixMilli() int64 {
    return this.Time.UnixNano() / 1e6
}

// 周天
func (this Date) Weekday() int {
    return int(this.Time.Weekday())
}

// 周
func (this Date) WeekdayStr() string {
    return Weeks[int(this.Time.Weekday())]
}

// 格式化
func (this Date) Format(str string) string {
    return this.Time.Format(this.FormatStr(str))
}

// 格式化字符为 go 对应时间字符
func (this Date) FormatStr(str string) string {
    var buffer bytes.Buffer

    for i := 0; i < len(str); i++ {
        val, ok := FormatStrs[str[i:i+1]]
        if ok {
            buffer.WriteString(val)
        } else {
            buffer.WriteString(str[i : i+1])
        }
    }

    return buffer.String()
}

// 返回字符
func (this Date) ToString(timezone ...string) string {
    if len(timezone) > 0 {
        return this.Location(timezone[0]).Time.String()
    }

    return this.Time.String()
}

// 默认返回
func (this Date) String() string {
    return this.TimeStr()
}

// =====

// 当前
func Now() Date {
    return Date{time.Now()}
}

// 时间戳
func Unix(sec int64, nsec int64) Date {
    return Date{time.Unix(sec, nsec)}
}

// 时间
func Time(t time.Time) Date {
    return Date{t}
}

// 日期
func Dates(day int, month int, year int) Date {
    return Date{
        time.Date(year, Months[month], day, 0, 0, 0, 0, time.UTC),
    }
}

// 日期时间
func Datetime(day int, month int, year int, hour int, min int, sec int) Date {
    return Date{
        time.Date(year, Months[month], day, hour, min, sec, 0, time.UTC),
    }
}

// 字符
func FromStr(str string, formatDatetime ...string) Date {
    var format = ""

    if len(formatDatetime) > 0 {
        format = formatDatetime[0]
    } else if len(formatDatetime) == 0 && len(str) == 19 {
        format = "Y-m-d H:i:s"
    } else if len(formatDatetime) == 0 && len(str) == 10 {
        format = "Y-m-d"
    } else {
        format = "Y-m-d"
    }

    date := Date{}

    format = date.FormatStr(format)
    time, err := time.Parse(format, str)
    if err != nil {
        return date
    }

    date.Time = time

    return date
}

// 当前日期时间字符
func NowDatetimeStr() string {
    return Now().DatetimeStr()
}

// 当前日期
func NowDateStr() string {
    return Now().DateStr()
}

// 当前时间字符
func NowTimeStr() string {
    return Now().TimeStr()
}
