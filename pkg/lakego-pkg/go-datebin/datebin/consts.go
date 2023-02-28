package datebin

import (
    "time"
)

// 时间常量
const (
    // 皮秒[ps] [Picosecond = Nanosecond * 0.001]
    Picosecond  = time.Nanosecond / 1000
    // 纳秒[ns] [Nanosecond time.Duration = 1]
    Nanosecond  = time.Nanosecond
    // 微妙[µs] [Microsecond = Nanosecond * 1000]
    Microsecond = time.Microsecond
    // 毫秒[ms] [Millisecond = Microsecond * 1000]
    Millisecond = time.Millisecond
    // 秒[s]    [Second = Millisecond * 1000]
    Second      = time.Second
    // 分钟[m]  [Minute = Second * 60]
    Minute      = time.Minute
    // 小时[h]  [Hour = Minute * 60]
    Hour        = time.Hour
    // 天[d]    [Day = Hour * 24]
    Day         = time.Hour * 24
    // 周[w]    [Week = Day * 7]
    Week        = Day * 7
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

    Majuro     = "Pacific/Majuro"      // 马朱罗
    Midway     = "Pacific/Midway"      // 中途岛
    Honolulu   = "Pacific/Honolulu"    // 檀香山
    Shanghai   = "Asia/Shanghai"       // 上海
    Chongqing  = "Asia/Chongqing"      // 重庆
    Harbin     = "Asia/Harbin"         // 哈尔滨
    HongKong   = "Asia/Hong_Kong"      // 香港
    Macao      = "Asia/Macao"          // 澳门
    Taipei     = "Asia/Taipei"         // 台北
    Tokyo      = "Asia/Tokyo"          // 日本-东京
    Saigon     = "Asia/Saigon"         // 西贡
    Seoul      = "Asia/Seoul"          // 首尔
    Bangkok    = "Asia/Bangkok"        // 泰国-曼谷
    HoChiMinh  = "Asia/Ho_Chi_Minh"    // 越南
    Pyongyang  = "Asia/Pyongyang"      // 韩国
    Dubai      = "Asia/Dubai"          // 迪拜
    NewYork    = "America/New_York"    // 纽约
    LosAngeles = "America/Los_Angeles" // 洛杉矶
    Chicago    = "America/Chicago"     // 芝加哥
    Santiago   = "America/Santiago"    // 圣地亚哥
    SaoPaulo   = "America/Sao_Paulo"   // 圣保罗
    Moscow     = "Europe/Moscow"       // 莫斯科
    London     = "Europe/London"       // 欧洲-伦敦
    Berlin     = "Europe/Berlin"       // 柏林
    Paris      = "Europe/Paris"        // 巴黎
    Rome       = "Europe/Rome"         // 罗马
    Athens     = "Europe/Athens"       // 东欧标准时间 (雅典)
    Helsinki   = "Europe/Helsinki"     // 东欧标准时间 (赫尔辛基)
    Minsk      = "Europe/Minsk"        // 明斯克
    Amsterdam  = "Europe/Amsterdam"    // 中欧标准时间 (阿姆斯特丹)
)

// 周常量
const (
    Monday    = "Monday"
    Tuesday   = "Tuesday"
    Wednesday = "Wednesday"
    Thursday  = "Thursday"
    Friday    = "Friday"
    Saturday  = "Saturday"
    Sunday    = "Sunday"
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
    AnsicFormat              = time.ANSIC
    UnixDateFormat           = time.UnixDate
    RubyDateFormat           = time.RubyDate
    RFC822Format             = time.RFC822
    RFC822ZFormat            = time.RFC822Z
    RFC850Format             = time.RFC850
    RFC1123Format            = time.RFC1123
    RFC1123ZFormat           = time.RFC1123Z
    RssFormat                = time.RFC1123Z
    RFC2822Format            = time.RFC1123Z
    KitchenFormat            = time.Kitchen
    RFC3339Format            = time.RFC3339
    StampFormat              = time.Stamp
    StampMilliFormat         = time.StampMilli
    StampMicroFormat         = time.StampMicro
    StampNanoFormat          = time.StampNano
    RFC3339MilliFormat       = "2006-01-02T15:04:05.999Z07:00"
    RFC3339MicroFormat       = "2006-01-02T15:04:05.999999Z07:00"
    RFC3339NanoFormat        = "2006-01-02T15:04:05.999999999Z07:00"
    CookieFormat             = "Monday, 02-Jan-2006 15:04:05 MST"
    ISO8601Format            = "2006-01-02T15:04:05-07:00"
    ISO8601MilliFormat       = "2006-01-02T15:04:05.999-07:00"
    ISO8601MicroFormat       = "2006-01-02T15:04:05.999999-07:00"
    ISO8601NanoFormat        = "2006-01-02T15:04:05.999999999-07:00"
    RFC1036Format            = "Mon, 02 Jan 06 15:04:05 -0700"
    RFC7231Format            = "Mon, 02 Jan 2006 15:04:05 GMT"
    DayDateTimeFormat        = "Mon, Jan 2, 2006 3:04 PM"
    FormattedDateFormat      = "Jan 2, 2006"
    DatetimeNanoFormat       = "2006-01-02 15:04:05.999999999"
    DatetimeMicroFormat      = "2006-01-02 15:04:05.999999"
    DatetimeMilliFormat      = "2006-01-02 15:04:05.999"
    DatetimeFormat           = "2006-01-02 15:04:05"
    DateFormat               = "2006-01-02"
    TimeFormat               = "15:04:05"
    HourMinuteFormat         = "15:04"
    HourFormat               = "15"
    ShortDatetimeNanoFormat  = "20060102150405.999999999"
    ShortDatetimeMicroFormat = "20060102150405.999999"
    ShortDatetimeMilliFormat = "20060102150405.999"
    ShortDatetimeFormat      = "20060102150405"
    ShortDateFormat          = "20060102"
    ShortTimeFormat          = "150405"
    ShortHourMinuteFormat    = "1504"
)
