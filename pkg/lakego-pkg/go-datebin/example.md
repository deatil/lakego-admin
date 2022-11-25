### 使用

常用的一些使用示例，更多示例可以点击 [文档](pkg.go.dev/github.com/deatil/go-datebin) 查看


#### 引入包

~~~go
import (
    "github.com/deatil/go-datebin/datebin"
)
~~~


#### 固定时间使用

~~~go
// 时区可不设置
timezone := datebin.UTC

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
    // FromTimestamp(int64(1652587697), timezone.
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
    // ParseWithFormat("2022-10-23 22:18:56", "Y-m-d H:i:s", timezone.
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

// 当前日期, string
data := datebin.NowDateString(timezone)

// 当前时间字符, string
data := datebin.NowTimeString(timezone)

// 时间戳转为 time.Time
timeData := datebin.TimestampToTime(int64(1652587697), timezone)

// 时间转换为时间戳
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
data := diffTime.Format("相差时间: {Y}-{m}-{d} {H}:{i}:{s}")
~~~


#### 常用加减时间

~~~go
// 准备时间
time := datebin.Parse("2022-10-23 22:18:56")

// 常用加减时间
date := time.SubYears(uint(2)).
    // SubYears(uint(2))
    // SubYearsNoOverflow(uint(2))
    // SubYear()
    // SubYearNoOverflow()

    // AddYears(uint(2))
    // AddYearsNoOverflow(uint(2))
    // AddYear()
    // AddYearNoOverflow()

    // SubMonths(uint(2))
    // SubMonthsNoOverflow(uint(2))
    // SubMonth()
    // SubMonthNoOverflow()

    // AddMonths(uint(2))
    // AddMonthsNoOverflow(uint(2))
    // AddMonth()
    // AddMonthNoOverflow()

    // SubWeekdays(uint(2))
    // SubWeekday()

    // AddWeekdays(uint(2))
    // AddWeekday()

    // SubDays(uint(2)) # 前 n 天
    // SubDay() # 前一天

    // AddDays(uint(2)) # 后 n 天
    // AddDay() # 后一天

    // SubHours(uint(2))
    // SubHour()

    // AddHours(uint(2))
    // AddHour()

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
