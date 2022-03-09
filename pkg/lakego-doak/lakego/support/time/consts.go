package time

import (
    "time"
)

// 时区常量
const (
    LocationLocal = "Local"
    LocationCET   = "CET"
    LocationEET   = "EET"
    LocationEST   = "EST"
    LocationGMT   = "GMT"
    LocationUTC   = "UTC"
    LocationUCT   = "UCT"
    LocationMST   = "MST"

    LocationCuba      = "Cuba"      // 古巴
    LocationEgypt     = "Egypt"     // 埃及
    LocationEire      = "Eire"      // 爱尔兰
    LocationGreenwich = "Greenwich" // 格林尼治
    LocationIceland   = "Iceland"   // 冰岛
    LocationIran      = "Iran"      // 伊朗
    LocationIsrael    = "Israel"    // 以色列
    LocationJamaica   = "Jamaica"   // 牙买加
    LocationJapan     = "Japan"     // 日本
    LocationLibya     = "Libya"     // 利比亚
    LocationPoland    = "Poland"    // 波兰
    LocationPortugal  = "Portugal"  // 葡萄牙
    LocationPRC       = "PRC"       // 中国
    LocationSingapore = "Singapore" // 新加坡
    LocationTurkey    = "Turkey"    // 土耳其

    LocationShanghai   = "Asia/Shanghai"       // 上海
    LocationChongqing  = "Asia/Chongqing"      // 重庆
    LocationHarbin     = "Asia/Harbin"         // 哈尔滨
    LocationHongKong   = "Asia/Hong_Kong"      // 香港
    LocationMacao      = "Asia/Macao"          // 澳门
    LocationTaipei     = "Asia/Taipei"         // 台北
    LocationTokyo      = "Asia/Tokyo"          // 东京
    LocationSaigon     = "Asia/Saigon"         // 西贡
    LocationSeoul      = "Asia/Seoul"          // 首尔
    LocationBangkok    = "Asia/Bangkok"        // 曼谷
    LocationDubai      = "Asia/Dubai"          // 迪拜
    LocationNewYork    = "America/New_York"    // 纽约
    LocationLosAngeles = "America/Los_Angeles" // 洛杉矶
    LocationChicago    = "America/Chicago"     // 芝加哥
    LocationMoscow     = "Europe/Moscow"       // 莫斯科
    LocationLondon     = "Europe/London"       // 伦敦
    LocationBerlin     = "Europe/Berlin"       // 柏林
    LocationParis      = "Europe/Paris"        // 巴黎
    LocationRome       = "Europe/Rome"         // 罗马
)

// 月份常量
const (
    DateJanuary   = "January"   // 一月
    DateFebruary  = "February"  // 二月
    DateMarch     = "March"     // 三月
    DateApril     = "April"     // 四月
    DateMay       = "May"       // 五月
    DateJune      = "June"      // 六月
    DateJuly      = "July"      // 七月
    DateAugust    = "August"    // 八月
    DateSeptember = "September" // 九月
    DateOctober   = "October"   // 十月
    DateNovember  = "November"  // 十一月
    DateDecember  = "December"  // 十二月
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
    FormattedDateFormat = "Jan 2, 2006"
    DatetimeFormat      = "2006-01-02 15:04:05"
    DateFormat          = "2006-01-02"
    TimeFormat          = "15:04:05"
    HourMinuteFormat    = "15:04"
    HourFormat          = "15"
    ShortDateTimeFormat = "20060102150405"
    ShortDateFormat     = "20060102"
    ShortTimeFormat     = "150405"
)
