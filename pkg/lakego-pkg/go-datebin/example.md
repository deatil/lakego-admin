### 使用

go-datebin 常用的一些使用示例。更多未提及方法可以 [点击文档](pkg.go.dev/github.com/deatil/go-datebin) 查看


### 目录

- [引入包](#引入包)
- [获取错误信息及常规数据获取和设置](#获取错误信息及常规数据获取和设置)
- [固定时间使用](#固定时间使用)
- [根据具体时间进行格式化](#根据具体时间进行格式化)
- [解析使用](#解析使用)
- [数据输出](#数据输出)
- [快捷方式](#快捷方式)
- [比较时间](#比较时间)
- [获取时间](#获取时间)
- [求两个时间差值](#求两个时间差值)
- [常用加减时间](#常用加减时间)
- [判断是否是](#判断是否是)
    - [判断是否是几月](#判断是否是几月)
    - [判断是否是某星座](#判断是否是某星座)
    - [判断是否是周几](#判断是否是周几)
    - [判断是否相等](#判断是否相等)
- [时间设置](#时间设置)
- [获取范围时间](#获取范围时间)


#### 引入包

~~~go
import (
    "github.com/deatil/go-datebin/datebin"
)
~~~


#### 获取错误信息及常规数据获取和设置

~~~go
var datebinErr error

// 方式1
date := datebin.
    Now().
    OnError(func(err error) {
        datebinErr = err
    }).
    ToDatetimeString()

// 方式2
err := datebin.
    Parse("2022-101-23 22:18:56").
    GetError()

// 常规数据设置及获取
datebin.WithTime(time time.Time) # 设置时间
datebin.GetTime() time.Time # 获取时间
datebin.WithWeekStartAt(weekday time.Weekday) # 设置周开始时间
datebin.GetWeekStartAt() time.Weekday # 获取周开始时间
datebin.WithLocation(loc *time.Location) # 设置时区
datebin.GetLocation() *time.Location # 获取时区
datebin.GetLocationString() string # 获取时区字符
datebin.WithTimezone(timezone string) # 设置时区
datebin.SetTimezone(timezone string) # 设置时区, 直接更改
datebin.UseLocTime() # 使用设置的时区
datebin.GetTimezone() # 获取时区 Zone 名称
datebin.GetOffset() # 获取距离UTC时区的偏移量，单位秒
datebin.GetError() # 获取错误信息
~~~


#### 固定时间使用

~~~go
// 时区可不设置
timezone := datebin.UTC

// 全局设置时区，对使用帮助函数有效
datebin.SetTimezone(timezone)

// 固定时间
date := datebin.
    Now().
    // Now(timezone).
    // Today(timezone).
    // Tomorrow(timezone).
    // Yesterday(timezone).
    ToDatetimeString()
~~~


#### 根据具体时间进行格式化

~~~go
import (
    "time"
)

// 时区可不设置
timezone := datebin.UTC

// 添加时间
date := datebin.
    FromTimeTime(time.Now(), timezone).
    // FromTimeUnix(int64(1652587697), int64(0), timezone).
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

~~~go
// 时区可不设置
timezone := datebin.UTC

// 解析时间
date := datebin.
    Parse("2022-10-23 22:18:56").
    // ParseWithLayout("2022-10-23 22:18:56", "2006-01-02 15:04:05", timezone).
    // ParseWithFormat("2022-10-23 22:18:56", "Y-m-d H:i:s", timezone).
    // ParseDatetimeString("2022-10-23 22:18:56", "2006-01-02 15:04:05").
    // ParseDatetimeString("2022-10-23 22:18:56", "Y-m-d H:i:s", "u").
    ToDatetimeString()
~~~


#### 数据输出

~~~go
// 时区可不设置
timezone := datebin.UTC

// 数据输出
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

~~~go
// 时区可不设置
timezone := datebin.UTC

// 当前时间，单位：秒, int64
data := datebin.NowTime(timezone)

// 当前日期时间字符, string
data := datebin.NowDatetimeString(timezone)

// 当前日期字符, string
data := datebin.NowDateString(timezone)

// 当前时间字符, string
data := datebin.NowTimeString(timezone)

// 时间戳转为 time.Time
timeData := datebin.TimestampToTime(int64(1652587697), timezone)

// time.Time 转换为时间戳
timestampData := datebin.TimeToTimestamp(timeData, timezone)

// 时间字符转为时间
timeData2 := datebin.StringToTime("2022-10-23 22:18:56", "2006-01-02 15:04:05")
timeData2 := datebin.StringToTime("2022-10-23 22:18:56", "Y-m-d H:i:s", "u")

// 时间字符转为时间戳
timestampData2 := datebin.StringToTimestamp("2022-10-23 22:18:56", "2006-01-02 15:04:05")
timestampData2 := datebin.StringToTimestamp("2022-10-23 22:18:56", "Y-m-d H:i:s", "u")
~~~


#### 比较时间

~~~go
// 准备时间
timeA := datebin.Parse("2022-10-23 22:18:56")
timeB := datebin.Parse("2022-10-25 23:18:56")
timeC := datebin.Parse("2022-10-26 23:18:56")

// timeA 大于 timeB
res := timeA.Gt(timeB)

// timeA 小于 timeB
res := timeA.Lt(timeB)

// timeA 等于 timeB
res := timeA.Eq(timeB)

// timeA 不等于 timeB
res := timeA.Ne(timeB)

// timeA 大于等于 timeB
res := timeA.Gte(timeB)

// timeA 小于等于 timeB
res := timeA.Lte(timeB)

// timeA 是否在两个时间之间(不包括这两个时间)
res := timeA.Between(timeB, timeC)

// timeA 是否在两个时间之间(包括这两个时间)
res := timeA.BetweenIncluded(timeB, timeC)

// timeA 是否在两个时间之间(包括开始时间)
res := timeA.BetweenIncludStart(timeB, timeC)

// timeA 是否在两个时间之间(包括结束时间)
res := timeA.BetweenIncludEnd(timeB, timeC)

// 最小值
res := timeA.Min(timeB)
res := timeA.Minimum(timeB)

// 最大值
res := timeA.Max(timeB)
res := timeA.Maximum(timeB)

// 平均值
res := timeA.Avg(timeB)
res := timeA.Average(timeB)

// 取 a 和 b 中与当前时间最近的一个
res := timeA.Closest(timeB, timeC)

// 取 a 和 b 中与当前时间最远的一个
res := timeA.Farthest(timeB, timeC)

// 年龄，可为负数
res := timeA.Age()

// 用于查找将规定的持续时间 'd' 舍入为 'm' 持续时间的最接近倍数的结果
res := timeA.Round(d time.Duration)

// 用于查找将规定的持续时间 'd' 朝零舍入到 'm' 持续时间的倍数的结果
res := timeA.Truncate(d time.Duration)
~~~


#### 获取时间

~~~go
// 准备时间
time := datebin.Parse("2022-10-23 22:18:56")

// 获取当前世纪
res := time.Century()

// 获取当前年代
res := time.Decade()

// 获取当前年
res := time.Year()

// 获取当前季度
res := time.Quarter()

// 获取当前月
res := time.Month()

// 星期几数字
res := time.Weekday()

// 获取当前日
res := time.Day()

// 获取当前小时
res := time.Hour()

// 获取当前分钟数
res := time.Minute()

// 获取当前秒数
res := time.Second()

// 获取当前毫秒数，范围[0, 999]
res := time.Millisecond()

// 获取当前微秒数，范围[0, 999999]
res := time.Microsecond()

// 获取当前纳秒数，范围[0, 999999999]
res := time.Nanosecond()

// 秒级时间戳，10位
res := time.Timestamp()
res := time.TimestampWithSecond()

// 毫秒级时间戳，13位
res := time.TimestampWithMillisecond()

// 微秒级时间戳，16位
res := time.TimestampWithMicrosecond()

// 纳秒级时间戳，19位
res := time.TimestampWithNanosecond()

// 返回年月日数据
year, month, day := time.Date()

// 返回时分秒数据
hour, minute, second := time.Time()

// 返回年月日时分秒数据
year, month, day, hour, minute, second := time.Datetime()

// 返回年月日时分秒数据带纳秒
year, month, day, hour, minute, second, nanosecond := time.DatetimeWithNanosecond()

// 返回年月日时分秒数据带微秒
year, month, day, hour, minute, second, microsecond := time.DatetimeWithMicrosecond()

// 返回年月日时分秒数据带毫秒
year, month, day, hour, minute, second, millisecond := time.DatetimeWithMillisecond()

// 获取本月的总天数
res := time.DaysInMonth()

// 获取本年的第几月
res := time.MonthOfYear()

// 获取本年的第几天
res := time.DayOfYear()

// 获取本月的第几天
res := time.DayOfMonth()

// 获取本周的第几天
res := time.DayOfWeek()

// 获取本年的第几周
res := time.WeekOfYear()
~~~


#### 求两个时间差值

~~~go
// 准备时间
timeA := datebin.Parse("2022-10-23 22:18:56")
timeB := datebin.Parse("2022-10-25 23:18:56")

diffTime := timeA.Diff(timeB)

// 相差秒
data := diffTime.Seconds()

// 相差秒，绝对值
data := diffTime.SecondsAbs()

// 其他
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

// 格式化输出
data := diffTime.Format("时间相差 {Y} 年")
data := diffTime.Format("时间相差 {m} 月")
data := diffTime.Format("时间相差 {d} 天")
data := diffTime.Format("时间相差 {H} 小时")
data := diffTime.Format("时间相差 {i} 分钟")
data := diffTime.Format("时间相差 {s} 秒")
~~~


#### 常用加减时间

~~~go
// 准备时间
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

~~~go
// 准备时间
time := datebin.Parse("2022-10-23 22:18:56")

// 是否是零值时间
res := time.IsZero()

// 是否是无效时间
res := time.IsInvalid()

// 是否是 UTC 时区
res := time.IsUTC()

// 是否是本地时区
res := time.IsLocal()

// 是否是当前时间
res := time.IsNow()

// 是否是未来时间
res := time.IsFuture()

// 是否是过去时间
res := time.IsPast()

// 是否是闰年
res := time.IsLeapYear()

// 是否是长年
res := time.IsLongYear()

// 是否是今天
res := time.IsToday()

// 是否是昨天
res := time.IsYesterday()

// 是否是明天
res := time.IsTomorrow()

// 是否是当年
res := time.IsCurrentYear()

// 是否是当月
res := time.IsCurrentMonth()

// 时间是否是当前最近的一周
res := time.IsLatelyWeek()

// 时间是否是当前最近的一个月
res := time.IsLatelyMonth()

// 是否是当前月最后一天
res := time.IsLastOfMonth()

// 是否当天开始
res := time.IsStartOfDay()

// 是否当天开始
res := time.IsStartOfDayWithMicrosecond()

// 是否当天结束
res := time.IsEndOfDay()

// 是否当天结束
res := time.IsEndOfDayWithMicrosecond()

// 是否是半夜
res := time.IsMidnight()

// 是否是中午
res := time.IsMidday()

// 是否是春季
res := time.IsSpring()

// 是否是夏季
res := time.IsSummer()

// 是否是秋季
res := time.IsAutumn()

// 是否是冬季
res := time.IsWinter()
~~~


#### 判断是否是几月

~~~go
// 准备时间
time := datebin.Parse("2022-10-23 22:18:56")

// 是否是一月
res := time.IsJanuary()

// 是否是二月
res := time.IsFebruary()

// 是否是三月
res := time.IsMarch()

// 是否是四月
res := time.IsApril()

// 是否是五月
res := time.IsMay()

// 是否是六月
res := time.IsJune()

// 是否是七月
res := time.IsJuly()

// 是否是八月
res := time.IsAugust()

// 是否是九月
res := time.IsSeptember()

// 是否是十月
res := time.IsOctober()

// 是否是十一月
res := time.IsNovember()

// 是否是十二月
res := time.IsDecember()
~~~


#### 判断是否是某星座

~~~go
// 准备时间
time := datebin.Parse("2022-10-23 22:18:56")

// 摩羯座
res := time.IsCapricornStar()

// 水瓶座
res := time.IsAquariusStar()

// 双鱼座
res := time.IsPiscesStar()

// 白羊座
res := time.IsAriesStar()

// 金牛座
res := time.IsTaurusStar()

// 双子座
res := time.IsGeminiStar()

// 巨蟹座
res := time.IsCancerStar()

// 狮子座
res := time.IsLeoStar()

// 处女座
res := time.IsVirgoStar()

// 天秤座
res := time.IsLibraStar()

// 天蝎座
res := time.IsScorpioStar()

// 射手座
res := time.IsSagittariusStar()
~~~


#### 判断是否是周几

~~~go
// 准备时间
time := datebin.Parse("2022-10-23 22:18:56")

// 是否是周一
res := time.IsMonday()

// 是否是周二
res := time.IsTuesday()

// 是否是周三
res := time.IsWednesday()

// 是否是周四
res := time.IsThursday()

// 是否是周五
res := time.IsFriday()

// 是否是周六
res := time.IsSaturday()

// 是否是周日
res := time.IsSunday()

// 是否是工作日
res := time.IsWeekday()

// 是否是周末
res := time.IsWeekend()
~~~


#### 判断是否相等

~~~go
// 准备时间
timeA := datebin.Parse("2022-10-23 22:18:56")
timeB := datebin.Parse("2022-10-25 23:18:56")

// 对比格式
format := "Y-m-d H:i:s"
layout := "2006-01-02 15:04:05"
unit := "year" // year | week | day | hour | minute | second | micro | microsecond

// 通过格式字符比对是否相等
res := timeA.IsSameAs(format, timeB)

// 通过布局字符比对是否相等
res := timeA.IsSameAsWithLayout(layout, timeB)

// 通过预设格式字符比对是否相等
res := timeA.IsSameUnit(unit, timeB)

// 是否同一年
res := timeA.IsSameYear(timeB)

// 是否是同一个月
res := timeA.IsSameMonth(timeB)

// 是否同一天
res := timeA.IsSameDay(timeB)

// 是否同一小时
res := timeA.IsSameHour(timeB)

// 是否同一分钟
res := timeA.IsSameMinute(timeB)

// 是否同一秒
res := timeA.IsSameSecond(timeB)

// 是否是同一年的同一个月
res := timeA.IsSameYearMonth(timeB)

// 是否是同一个月的同一天
res := timeA.IsSameMonthDay(timeB)

// 是否是同一年的同一个月的同一天
res := timeA.IsSameYearMonthDay(timeB)

// 是否是相同生日日期
res := timeA.IsSameBirthday(timeB)
~~~


#### 时间设置

~~~go
// 准备时间
time := datebin.Parse("2022-10-23 22:18:56")

// 预设周几
// datebin.Monday | datebin.Tuesday | datebin.Wednesday
// datebin.Thursday | datebin.Friday | datebin.Saturday
// datebin.Sunday 
day := datebin.Monday

// 设置一周的开始日期
res := time.SetWeekStartsAt(day)

// 日期时间带纳秒
res := time.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond)

// 日期时间带微秒
res := time.SetDatetimeWithMicrosecond(year, month, day, hour, minute, second, microsecond)

// 日期时间带毫秒
res := time.SetDatetimeWithMillisecond(year, month, day, hour, minute, second, millisecond)

// 日期时间
res := time.SetDatetime(year, month, day, hour, minute, second)

// 日期
res := time.SetDate(year, month, day)

// 时间
res := time.SetTime(hour, minute, second)

// 设置年份
res := time.SetYear(year)

// 设置月份
res := time.SetMonth(month)

// 设置天
res := time.SetDay(day)

// 设置小时
res := time.SetHour(hour)

// 设置分钟
res := time.SetMinute(minute)

// 设置秒数
res := time.SetSecond(second)

// 设置毫秒
res := time.SetMillisecond(millisecond)

// 设置微秒
res := time.SetMicrosecond(microsecond)

// 设置纳秒
res := time.SetNanosecond(nanosecond)

// 显示设置后的时间
date := res.ToDatetimeString()
~~~


#### 获取范围时间

~~~go
// 准备时间
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
