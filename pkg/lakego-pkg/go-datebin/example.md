### 使用 / Use

go-datebin 常用的一些使用示例。更多未提及方法可以 [点击文档](https://pkg.go.dev/github.com/deatil/go-datebin) 查看

go-datebin some using example, more see [docs](https://pkg.go.dev/github.com/deatil/go-datebin)


### 目录 / Index

- [引入包/import](#引入包)
- [获取错误信息/Get Errors](#获取错误信息)
- [常规数据获取和设置/Data get and set](#常规数据获取和设置)
- [固定时间使用/Today more](#固定时间使用)
- [输入时间/Input](#输入时间)
- [解析使用/Parse](#解析使用)
- [数据输出/Output](#数据输出)
- [快捷方式/Helper](#快捷方式)
- [比较时间/Compare](#比较时间)
- [获取时间/Get Time](#获取时间)
- [求两个时间差值/Diff Time](#求两个时间差值)
- [常用加减时间/Add Or Sub](#常用加减时间)
- [判断是否是/If](#判断是否是)
    - [判断是否是几月/If Month](#判断是否是几月)
    - [判断是否是某星座/If Star](#判断是否是某星座)
    - [判断是否是周几/If Week](#判断是否是周几)
    - [判断是否相等/If Eq](#判断是否相等)
- [时间设置/Setting](#时间设置)
- [获取范围时间/Between](#获取范围时间)
- [范围时间/Datetimes](#范围时间)
- [格式化符号表/Format type](#格式化符号表)


#### 引入包

import pkg

~~~go
import (
    "github.com/deatil/go-datebin/datebin"
)
~~~


#### 获取错误信息

get error list

~~~go
// 方式1 / type 1
var datebinErrs []error
date := datebin.
    Now().
    OnError(func(err []error) {
        datebinErrs = err
    }).
    ToDatetimeString()

// 方式2 / type 2
errs := datebin.
    Parse("2022-101-23 22:18:56").
    GetErrors()

// 方式3 / type 3
err := datebin.
    Parse("2022-101-23 22:18:56").
    Error()
if err != nil {
    errStr := err.Error()
}
~~~


#### 常规数据获取和设置

get data and set

~~~go
// 设置时间 / WithTime
datebin.WithTime(time time.Time)
// 获取时间 / GetTime
datebin.GetTime() time.Time
// 设置周开始时间 / WithWeekStartAt
datebin.WithWeekStartAt(weekday time.Weekday)
// 获取周开始时间 / GetWeekStartAt
datebin.GetWeekStartAt() time.Weekday
// 设置时区 / WithLocation
datebin.WithLocation(loc *time.Location)
// 获取时区 / GetLocation
datebin.GetLocation() *time.Location
// 获取时区字符 / GetLocationString
datebin.GetLocationString() string
// 设置时区 / WithTimezone
datebin.WithTimezone(timezone string)
// 设置时区, 直接更改 / SetTimezone
datebin.SetTimezone(timezone string)
// 使用设置的时区 / use seted loc
datebin.NewTime()
// 获取时区 Zone 名称 / GetTimezone
datebin.GetTimezone() string
// 获取距离UTC时区的偏移量，单位秒 / GetOffset
datebin.GetOffset() int
// 获取错误信息 / get errors
datebin.GetErrors() []error
// 添加错误信息 / add error
datebin.AppendError(err ...error) Datebin
// 获取错误, `error` 接口错误 / error interface
datebin.Error() error
~~~


#### 固定时间使用

some const example
~~~go
// 时区可不设置 / UTC timezone
timezone := datebin.UTC

// 全局设置时区，对使用帮助函数有效 / global set timezone
datebin.SetTimezone(timezone)

// 固定时间 / const funcs
date := datebin.
    Now().
    // Now(timezone).
    // Today(timezone).
    // Tomorrow(timezone).
    // Yesterday(timezone).
    ToDatetimeString()
~~~


#### 输入时间

input time

~~~go
import (
    "time"
)

// 时区可不设置 / timezone
timezone := datebin.UTC

// 添加时间 / from time
date := datebin.
    FromStdTime(time.Now(), timezone).
    // FromStdUnix(int64(1652587697), int64(0), timezone).
    // FromTimestamp(int64(1652587697), timezone).
    // FromDatetimeWithNanosecond(2022, 10, 23, 22, 18, 56, 123, timezone).
    // FromDatetimeWithMicrosecond(2022, 10, 23, 22, 18, 56, 123, timezone).
    // FromDatetimeWithMillisecond(2022, 10, 23, 22, 18, 56, 123, timezone).
    // FromDatetime(2022, 10, 23, 22, 18, 56, timezone).
    // FromDate(2022, 10, 23, timezone).
    // FromTime(22, 18, 56, timezone).
    ToDatetimeString()
~~~


#### 解析使用

parse time

~~~go
// 时区可不设置 / timezone
timezone := datebin.UTC

// 解析时间 / parse time
date := datebin.
    Parse("2022-10-23 22:18:56").
    // ParseWithLayout("2022-10-23 22:18:56", "2006-01-02 15:04:05", timezone).
    // ParseWithFormat("2022-10-23 22:18:56", "Y-m-d H:i:s", timezone).
    // ParseDatetimeString("2022-10-23 22:18:56", "2006-01-02 15:04:05").
    // ParseDatetimeString("2022-10-23 22:18:56", "Y-m-d H:i:s", "u").
    ToDatetimeString()
~~~


#### 数据输出

output time string

~~~go
// 时区可不设置 / timezone
timezone := datebin.UTC

// 数据输出 / output time string
date := datebin.
    Parse("2022-10-23 22:18:56").
    // String()
    // ToString(timezone) # 返回字符
    // ToStarString(timezone) # 返回星座名称
    // ToSeasonString(timezone) # 返回当前季节，以气象划分
    // ToWeekdayString(timezone) # 周几
    // Layout("2006-01-02 15:04:05", timezone) # 原始格式
    // ToLayoutString("2006-01-02 15:04:05", timezone) # 原始格式
    // Format("Y-m-d H:i:s", timezone) # 输出指定布局的时间字符串
    // ToFormatString("Y-m-d H:i:s", timezone) # 输出指定布局的时间字符串
    // ToAnsicString()
    // ToUnixDateString()
    // ToRubyDateString()
    // ToRFC822String()
    // ToRFC822ZString()
    // ToRFC850String()
    // ToRFC1123String()
    // ToRFC1123ZString()
    // ToRssString()
    // ToRFC2822String()
    // ToRFC3339String()
    // ToKitchenString()
    // ToCookieString()
    // ToISO8601String()
    // ToRFC1036String()
    // ToRFC7231String()
    // ToAtomString()
    // ToW3CString()
    // ToDayDateTimeString()
    // ToFormattedDateString()
    // ToDatetimeString()
    // ToDateString()
    // ToTimeString()
    // ToShortDatetimeString()
    // ToShortDateString()
    // ToShortTimeString()
    ToDatetimeString()
~~~


#### 快捷方式

some helpers

~~~go
// 时区可不设置 / timezone
timezone := datebin.UTC

// 当前时间，单位：秒, int64 / now time timestamp
var data int64 = datebin.NowTime(timezone)

// 当前日期时间字符, string / now Datetime string
var data string = datebin.NowDatetimeString(timezone)

// 当前日期字符, string / now date string
var data string = datebin.NowDateString(timezone)

// 当前时间字符, string / now time string
var data string = datebin.NowTimeString(timezone)

// 时间戳转为 time.Time / timestamp to time.Time
var timeData time.Time = datebin.TimestampToTime(int64(1652587697), timezone)

// time.Time 转换为时间戳 / time.Time to timestamp
var timestampData int64 = datebin.TimeToTimestamp(timeData, timezone)

// 时间字符转为时间 / String time To time.Time
var timeData2 time.Time = datebin.StringToTime("2022-10-23 22:18:56", "2006-01-02 15:04:05")
var timeData2 time.Time = datebin.StringToTime("2022-10-23 22:18:56", "Y-m-d H:i:s", "u")

// 时间字符转为时间戳 / String time To Timestamp
var timestampData2 int64 = datebin.StringToTimestamp("2022-10-23 22:18:56", "2006-01-02 15:04:05")
var timestampData2 int64 = datebin.StringToTimestamp("2022-10-23 22:18:56", "Y-m-d H:i:s", "u")
~~~


#### 比较时间

Compare 2 times

~~~go
// 准备时间 / some times
timeA := datebin.Parse("2022-10-23 22:18:56")
timeB := datebin.Parse("2022-10-25 23:18:56")
timeC := datebin.Parse("2022-10-26 23:18:56")

// timeA 大于 timeB / timeA Gt timeB
res := timeA.Gt(timeB)

// timeA 小于 timeB / timeA Lt timeB
res := timeA.Lt(timeB)

// timeA 等于 timeB / timeA Eq timeB
res := timeA.Eq(timeB)

// timeA 不等于 timeB / timeA Ne timeB
res := timeA.Ne(timeB)

// timeA 大于等于 timeB / timeA Gte timeB
res := timeA.Gte(timeB)

// timeA 小于等于 timeB / timeA Lte timeB
res := timeA.Lte(timeB)

// timeA 是否在两个时间之间(不包括这两个时间) / Between times
res := timeA.Between(timeB, timeC)

// timeA 是否在两个时间之间(包括这两个时间) / Between Included times
res := timeA.BetweenIncluded(timeB, timeC)

// timeA 是否在两个时间之间(包括开始时间) / Between Includ Start time
res := timeA.BetweenIncludStart(timeB, timeC)

// timeA 是否在两个时间之间(包括结束时间) / Between Includ End time
res := timeA.BetweenIncludEnd(timeB, timeC)

// 最小值 / Min
res := timeA.Min(timeB)
res := timeA.Minimum(timeB)

// 最大值 / Max
res := timeA.Max(timeB)
res := timeA.Maximum(timeB)

// 平均值 / Avg
res := timeA.Avg(timeB)
res := timeA.Average(timeB)

// 取 a 和 b 中与当前时间最近的一个 / a or b is the time Closest time
res := timeA.Closest(timeB, timeC)

// 取 a 和 b 中与当前时间最远的一个 / a or b is the time Farthest time
res := timeA.Farthest(timeB, timeC)

// 年龄，可为负数 / age
res := timeA.Age()

// 用于查找将规定的持续时间 'd' 舍入为 'm' 持续时间的最接近倍数的结果 / Round
res := timeA.Round(d time.Duration)

// 用于查找将规定的持续时间 'd' 朝零舍入到 'm' 持续时间的倍数的结果 / Truncate
res := timeA.Truncate(d time.Duration)
~~~


#### 获取时间

get time data

~~~go
// 准备时间 / time
time := datebin.Parse("2022-10-23 22:18:56")

// 获取当前世纪 / Century
res := time.Century()

// 获取当前年代 / Decade
res := time.Decade()

// 获取当前年 / Year
res := time.Year()

// 获取当前季度 / Quarter
res := time.Quarter()

// 获取当前月 / Month
res := time.Month()

// 星期几数字 / Weekday
res := time.Weekday()

// 获取当前日 / Day
res := time.Day()

// 获取当前小时 / Hour
res := time.Hour()

// 获取当前分钟数 / Minute
res := time.Minute()

// 获取当前秒数 / Second
res := time.Second()

// 获取当前毫秒数，范围[0, 999] / Millisecond [0, 999]
res := time.Millisecond()

// 获取当前微秒数，范围[0, 999999] / Microsecond [0, 999999]
res := time.Microsecond()

// 获取当前纳秒数，范围[0, 999999999] / Nanosecond [0, 999999999]
res := time.Nanosecond()

// 秒级时间戳，10位 / Timestamp
res := time.Timestamp()
res := time.TimestampWithSecond()

// 毫秒级时间戳，13位 / TimestampWithMillisecond
res := time.TimestampWithMillisecond()

// 微秒级时间戳，16位 / TimestampWithMicrosecond
res := time.TimestampWithMicrosecond()

// 纳秒级时间戳，19位 / TimestampWithNanosecond
res := time.TimestampWithNanosecond()

// 返回年月日数据 / year, month, day
year, month, day := time.Date()

// 返回时分秒数据 / hour, minute, second
hour, minute, second := time.Time()

// 返回年月日时分秒数据 / year, month, day, hour, minute, second
year, month, day, hour, minute, second := time.Datetime()

// 返回年月日时分秒数据带纳秒 / get year, month, day, hour, minute, second, nanosecond
year, month, day, hour, minute, second, nanosecond := time.DatetimeWithNanosecond()

// 返回年月日时分秒数据带微秒 / get year, month, day, hour, minute, second, microsecond
year, month, day, hour, minute, second, microsecond := time.DatetimeWithMicrosecond()

// 返回年月日时分秒数据带毫秒 / get year, month, day, hour, minute, second, millisecond
year, month, day, hour, minute, second, millisecond := time.DatetimeWithMillisecond()

// 获取本月的总天数 / the Month days
res := time.DaysInMonth()

// 获取本年的第几月 / MonthOfYear
res := time.MonthOfYear()

// 获取本年的第几天 / DayOfYear
res := time.DayOfYear()

// 获取本月的第几天 / DayOfMonth
res := time.DayOfMonth()

// 获取本周的第几天 / DayOfWeek
res := time.DayOfWeek()

// 获取本年的第几周 / WeekOfYear
res := time.WeekOfYear()
~~~


#### 求两个时间差值

two times Diff

~~~go
// 准备时间 / some times
timeA := datebin.Parse("2022-10-23 22:18:56")
timeB := datebin.Parse("2022-10-25 23:18:56")

diffTime := timeA.Diff(timeB)

// 相差秒 / diff Seconds
data := diffTime.Seconds()

// 相差秒，绝对值 / diff Seconds abs
data := diffTime.SecondsAbs()

// 其他 / others
data := diffTime.Minutes()
data := diffTime.MinutesAbs()
data := diffTime.Hours()
data := diffTime.HoursAbs()
data := diffTime.Days()
data := diffTime.DaysAbs()
data := diffTime.Weeks()
data := diffTime.WeeksAbs()
data := diffTime.Months()
data := diffTime.MonthsAbs()
data := diffTime.Years()
data := diffTime.YearsAbs()

// 格式化输出 / format output
data := diffTime.Format("{Y} years ago")
data := diffTime.Format("{m} Months ago")
data := diffTime.Format("{d} Days ago")
data := diffTime.Format("{H} Hours ago")
data := diffTime.Format("{i} Minutes ago")
data := diffTime.Format("{s} Seconds ago")
data := timeA.Diff(timeB).Format("{dd} Day {HH} Hour {ii} Minute {ss} Second ago")
data := timeA.Diff(timeB).Format("{WW} week {DD} Day {HH} Hour {ii} Minute {ss} Second ago")
~~~


#### 常用加减时间

add or sub time

~~~go
// 准备时间 / some times
time := datebin.Parse("2022-10-23 22:18:56")

// 常用加减时间
date := time.SubYears(uint(2)). # 年
    // SubYears(uint(2))
    // SubYearsNoOverflow(uint(2))
    // SubYear()
    // SubYearNoOverflow()

    // AddYears(uint(2))
    // AddYearsNoOverflow(uint(2))
    // AddYear()
    // AddYearNoOverflow()

    // 月份
    // SubMonths(uint(2))
    // SubMonthsNoOverflow(uint(2))
    // SubMonth()
    // SubMonthNoOverflow()

    // AddMonths(uint(2))
    // AddMonthsNoOverflow(uint(2))
    // AddMonth()
    // AddMonthNoOverflow()

    // 周
    // SubWeekdays(uint(2))
    // SubWeekday()

    // AddWeekdays(uint(2))
    // AddWeekday()

    // 天
    // SubDays(uint(2)) # 前 n 天
    // SubDay() # 前一天

    // AddDays(uint(2)) # 后 n 天
    // AddDay() # 后一天

    // 小时
    // SubHours(uint(2))
    // SubHour()

    // AddHours(uint(2))
    // AddHour()

    // 分钟
    // SubMinutes(uint(2))
    // SubMinute()

    // AddMinutes(uint(2))
    // AddMinute()

    // 秒
    // SubSeconds(uint(2))
    // SubSecond()

    // AddSeconds(uint(2))
    // AddSecond()

    // 毫秒
    // SubMilliseconds(uint(2))
    // SubMillisecond()

    // AddMilliseconds(uint(2))
    // AddMillisecond()

    // 微妙
    // SubMicroseconds(uint(2))
    // SubMicrosecond()

    // AddMicroseconds(uint(2))
    // AddMicrosecond()

    // 纳秒
    // SubNanoseconds(uint(2))
    // SubNanosecond()

    // AddNanoseconds(uint(2))
    // AddNanosecond()

    ToDatetimeString()
~~~


#### 判断是否是

if time

~~~go
// 准备时间 / some times
time := datebin.Parse("2022-10-23 22:18:56")

// 是否是零值时间 / IsZero
res := time.IsZero()

// 是否是无效时间 / IsInvalid
res := time.IsInvalid()

// 是否是 UTC 时区 / IsUTC timezone
res := time.IsUTC()

// 是否是本地时区 / IsLocal timezone
res := time.IsLocal()

// 是否是当前时间 / IsNow
res := time.IsNow()

// 是否是未来时间 / IsFuture
res := time.IsFuture()

// 是否是过去时间 / IsPast
res := time.IsPast()

// 是否是闰年 / IsLeapYear
res := time.IsLeapYear()

// 是否是长年 / IsLongYear
res := time.IsLongYear()

// 是否是今天 / IsToday
res := time.IsToday()

// 是否是昨天 / IsYesterday
res := time.IsYesterday()

// 是否是明天 / IsTomorrow
res := time.IsTomorrow()

// 是否是当年 / IsCurrentYear
res := time.IsCurrentYear()

// 是否是当月 / IsCurrentMonth
res := time.IsCurrentMonth()

// 时间是否是当前最近的一周 / IsLatelyWeek
res := time.IsLatelyWeek()

// 时间是否是当前最近的一个月 / IsLatelyMonth
res := time.IsLatelyMonth()

// 是否是当前月最后一天 / IsLastOfMonth
res := time.IsLastOfMonth()

// 是否当天开始 / IsStartOfDay
res := time.IsStartOfDay()

// 是否当天开始 / IsStartOfDayWithMicrosecond
res := time.IsStartOfDayWithMicrosecond()

// 是否当天结束 / IsEndOfDay
res := time.IsEndOfDay()

// 是否当天结束 / IsEndOfDayWithMicrosecond
res := time.IsEndOfDayWithMicrosecond()

// 是否是半夜 / IsMidnight
res := time.IsMidnight()

// 是否是中午 / IsMidday
res := time.IsMidday()

// 是否是春季 / IsSpring
res := time.IsSpring()

// 是否是夏季 / IsSummer
res := time.IsSummer()

// 是否是秋季 / IsAutumn
res := time.IsAutumn()

// 是否是冬季 / IsWinter
res := time.IsWinter()
~~~


#### 判断是否是几月

if month

~~~go
// 准备时间 / some times
time := datebin.Parse("2022-10-23 22:18:56")

// 是否是一月 / IsJanuary
res := time.IsJanuary()

// 是否是二月 / IsFebruary
res := time.IsFebruary()

// 是否是三月 / IsMarch
res := time.IsMarch()

// 是否是四月 / IsApril
res := time.IsApril()

// 是否是五月 / IsMay
res := time.IsMay()

// 是否是六月 / IsJune
res := time.IsJune()

// 是否是七月 / IsJuly
res := time.IsJuly()

// 是否是八月 / IsAugust
res := time.IsAugust()

// 是否是九月 / IsSeptember
res := time.IsSeptember()

// 是否是十月 / IsOctober
res := time.IsOctober()

// 是否是十一月 / IsNovember
res := time.IsNovember()

// 是否是十二月 / IsDecember
res := time.IsDecember()
~~~


#### 判断是否是某星座

if star

~~~go
// 准备时间 / some time
time := datebin.Parse("2022-10-23 22:18:56")

// 摩羯座 / IsCapricornStar
res := time.IsCapricornStar()

// 水瓶座 / IsAquariusStar
res := time.IsAquariusStar()

// 双鱼座 / IsPiscesStar
res := time.IsPiscesStar()

// 白羊座 / IsAriesStar
res := time.IsAriesStar()

// 金牛座 / IsTaurusStar
res := time.IsTaurusStar()

// 双子座 / IsGeminiStar
res := time.IsGeminiStar()

// 巨蟹座 / IsCancerStar
res := time.IsCancerStar()

// 狮子座 / IsLeoStar
res := time.IsLeoStar()

// 处女座 / IsVirgoStar
res := time.IsVirgoStar()

// 天秤座 / IsLibraStar
res := time.IsLibraStar()

// 天蝎座 / IsScorpioStar
res := time.IsScorpioStar()

// 射手座 / IsSagittariusStar
res := time.IsSagittariusStar()
~~~


#### 判断是否是周几

~~~go
time := datebin.Parse("2022-10-23 22:18:56")

// 是否是周一 / IsMonday
res := time.IsMonday()

// 是否是周二 / IsTuesday
res := time.IsTuesday()

// 是否是周三 / IsWednesday
res := time.IsWednesday()

// 是否是周四 / IsThursday
res := time.IsThursday()

// 是否是周五 / IsFriday
res := time.IsFriday()

// 是否是周六 / IsSaturday
res := time.IsSaturday()

// 是否是周日 / IsSunday
res := time.IsSunday()

// 是否是工作日 / IsWeekday
res := time.IsWeekday()

// 是否是周末 / IsWeekend
res := time.IsWeekend()
~~~


#### 判断是否相等

if some times is equal

~~~go
timeA := datebin.Parse("2022-10-23 22:18:56")
timeB := datebin.Parse("2022-10-25 23:18:56")

// 对比格式 / for format
format := "Y-m-d H:i:s"
layout := "2006-01-02 15:04:05"
unit := "year" // year | week | day | hour | minute | second | micro | microsecond

// 通过格式字符比对是否相等 / for format
res := timeA.IsSameAs(format, timeB)

// 通过布局字符比对是否相等 / for layout
res := timeA.IsSameAsWithLayout(layout, timeB)

// 通过预设格式字符比对是否相等 / for unit
res := timeA.IsSameUnit(unit, timeB)

// 是否同一年 / IsSameYear
res := timeA.IsSameYear(timeB)

// 是否是同一个月 / IsSameMonth
res := timeA.IsSameMonth(timeB)

// 是否同一天 / IsSameDay
res := timeA.IsSameDay(timeB)

// 是否同一小时 / IsSameHour
res := timeA.IsSameHour(timeB)

// 是否同一分钟 / IsSameMinute
res := timeA.IsSameMinute(timeB)

// 是否同一秒 / IsSameSecond
res := timeA.IsSameSecond(timeB)

// 是否是同一年的同一个月 / IsSameYearMonth
res := timeA.IsSameYearMonth(timeB)

// 是否是同一个月的同一天 / IsSameMonthDay
res := timeA.IsSameMonthDay(timeB)

// 是否是同一年的同一个月的同一天 / IsSameYearMonthDay
res := timeA.IsSameYearMonthDay(timeB)

// 是否是相同生日日期 / IsSameBirthday
res := timeA.IsSameBirthday(timeB)
~~~


#### 时间设置

set time data

~~~go
time := datebin.Parse("2022-10-23 22:18:56")

// 预设周几 / datebin weeks
// datebin.Monday | datebin.Tuesday | datebin.Wednesday
// datebin.Thursday | datebin.Friday | datebin.Saturday
// datebin.Sunday
day := datebin.Monday

// 设置一周的开始日期 / set WeekStart
res := time.SetWeekStartsAt(day int)

// 日期时间带纳秒 / SetDatetimeWithNanosecond
res := time.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond int)

// 日期时间带微秒 / SetDatetimeWithMicrosecond
res := time.SetDatetimeWithMicrosecond(year, month, day, hour, minute, second, microsecond int)

// 日期时间带毫秒 / SetDatetimeWithMillisecond
res := time.SetDatetimeWithMillisecond(year, month, day, hour, minute, second, millisecond int)

// 日期时间 / SetDatetime
res := time.SetDatetime(year, month, day, hour, minute, second int)

// 日期 / SetDate
res := time.SetDate(year, month, day int)

// 时间 / SetTime
res := time.SetTime(hour, minute, second int)

// 设置年份 / SetYear
res := time.SetYear(year int)

// 设置月份 / SetMonth
res := time.SetMonth(month int)

// 设置天 / SetDay
res := time.SetDay(day int)

// 设置小时 / SetHour
res := time.SetHour(hour int)

// 设置分钟 / SetMinute
res := time.SetMinute(minute int)

// 设置秒数 / SetSecond
res := time.SetSecond(second int)

// 设置毫秒 / SetMillisecond
res := time.SetMillisecond(millisecond int)

// 设置微秒 / SetMicrosecond
res := time.SetMicrosecond(microsecond int)

// 设置纳秒 / SetNanosecond
res := time.SetNanosecond(nanosecond int)

// 显示设置后的时间 / output
date := res.ToDatetimeString()
~~~


#### 获取范围时间

get time data

~~~go
res := datebin.Parse("2022-10-23 22:18:56").
    NYearStart(2). # 当前n年开始
    // NYearEnd(2). # 当前n年结束
    // CenturyStart(). # 当前百年开始
    // CenturyEnd(). # 当前百年结束
    // DecadeStart(). # 当前十年开始
    // DecadeEnd(). # 当前十年结束
    // YearStart(). # 本年开始
    // YearEnd(). # 本年结束
    // SeasonStart(). # 本季节开始时间
    // SeasonEnd(). # 本季节结束时间
    // MonthStart(). # 本月开始时间
    // MonthEnd(). # 本月结束时间
    // WeekStart(). # 本周开始
    // WeekEnd(). # 本周结束
    // DayStart(). # 本日开始时间
    // DayEnd(). # 本日结束时间
    // HourStart(). # 小时开始时间
    // HourEnd(). # 小时结束时间
    // MinuteStart(). # 分钟开始时间
    // MinuteEnd(). # 分钟结束时间
    // SecondStart(). # 秒开始时间
    // SecondEnd(). # 秒结束时间
    ToDatetimeString()
~~~

#### 范围时间

range datetimes

~~~go
import (
    "github.com/deatil/go-datebin/datetimes"
)

start := datebin.Parse("2022-10-23 22:18:56")
end := datebin.Parse("2023-10-23 22:18:56")

d1 := datetimes.New(start, end)
d2 := datetimes.New(start1, end1)

// 求交集 / Intersection
var res Datetimes = d1.Intersection(d2)

// 求并集 / Union
var res []Datetimes = d1.Union(d2)

// d1 是否包含 d2 / d1 IsContain d2
var res bool = d1.IsContain(d2)

// 范围长度 / Length
var res int64 = d1.Length()

// 范围长度纳米 / LengthWithNanosecond
var res int64 = d1.LengthWithNanosecond()

// d1 大于 d2 / d1 Gt d2
var res bool = d1.Gt(d2)

// d1 小于 d2 / d1 Lt d2
var res bool = d1.Lt(d2)

// d1 等于 d2 / d1 Eq d2
var res bool = d1.Eq(d2)

// d1 不等于 d2 / d1 Ne d2
var res bool = d1.Ne(d2)

// d1 大于等于 d2 / d1 Gte d2
var res bool = d1.Gte(d2)

// d1 小于等于 d2 / d1 Lte d2
var res bool = d1.Lte(d2)
~~~


#### 格式化符号表

| 符号 | 描述 |  长度 | 范围 | 示例 |
| :------------: | :------------: | :------------: | :------------: | :------------: |
| c | ISO8601 格式日期 | - | - | 2006-01-02T15:04:05-07:00 |
| r | RFC2822 格式日期 | - | - | Mon, 02 Jan 2006 15:04:05 -0700 |
| Y | 4 位数字完整表示的年份 | 4 | 0000-9999 | 2016 |
| y | 2 位数字表示的年份 | 2 | 00-99 | 07 |
| m | 数字表示的月份，有前导零 | 2 | 01-12 | 01 |
| M | 缩写单词表示的月份 | 3 | Jan-Dec | Dec |
| n | 数字表示的月份，没有前导零 | - | 1-12 | 2 |
| d | 月份中的第几天，有前导零 | 2 | 01-31 | 05 |
| D | 缩写单词表示的周几 | 3 | Mon-Sun | Mon |
| j | 月份中的第几天，没有前导零 | - |1-31 | 2 |
| h | 小时，12 小时格式 | 2 | 00-11 | 03 |
| H | 小时，24 小时格式 | 2 | 00-23 | 15 |
| g | 小时，12 小时格式 | - | 1-12 | 3 |
| G | 小时，24 小时格式 | - | 0-23 | 15 |
| i | 分钟 | 2 | 01-59 | 04 |
| s | 秒数 | 2 | 01-59 | 05 |
| a | 小写的上午和下午标识 | 2 | am/pm | pm |
| A | 大写的上午和下午标识 | 2 | AM/PM | AM |
| e | 当前位置 | - | - | America/New_York |
| S | 第几天的英文缩写后缀 | 2 | st/nd/rd/th | rd |
| l | 完整单词表示的周几 | - | Monday-Sunday | Monday |
| F | 完整单词表示的月份 | - | January-December | January |
| O | 与格林威治时间相差的小时数 | - | - | -0700 |
| P | 与格林威治时间相差的小时数，小时和分钟之间有冒号分隔 | - | - | +07:00 |
| T | 时区缩写 | - | - | MST |
| W | ISO8601 格式数字表示的年份中的第几周 | - | 1-52 | 1 |
| N | ISO8601 格式数字表示的星期中的第几天 | 1 | 1-7 | 1 |
| L | 是否为闰年，如果是闰年为 ly，否则为 nly | - | ly/nly | nly |
| U | 秒级时间戳 | 10 | - | 1611818268 |
| u | 微秒 | 6 | 000000-999999 | 111999 |
| w | 数字表示的周几 | 1 | 0-6 | 1 |
| t | 月份中的总天数 | 2 | 28-31 | 29 |
| z | 年份中的第几天 | - | 0-365 | 3 |
| Q | 当前季节 | 1 | 1-4 | 2 |
| C | 当前世纪数 | - | 0-99 | 22 |
