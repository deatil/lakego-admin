### Docs

go-datebin some using example, more see [docs](https://pkg.go.dev/github.com/deatil/go-datebin)

[中文](docs_cn.md) | English


### Index

- [Import](#Import)
- [Get Errors](#GetErrors)
- [Data get and set](#GetAndSetData)
- [Today more](#TodayAndMore)
- [Input](#Input)
- [Parse](#Parse)
- [Output](#Output)
- [Helper](#Helper)
- [Compare](#Compare)
- [Get Time](#GetTime)
- [Diff Time](#DiffTime)
- [Add Or Sub](#AddOrSub)
- [Is](#Is)
    - [IsMonth](#IsMonth)
    - [IsStar](#IsStar)
    - [IsWeek](#IsWeek)
    - [IsEqual](#IsEqual)
- [Setting](#Setting)
- [Get Between](#GetBetween)
- [Datetimes](#Datetimes)
- [Format With Sign](#FormatWithSign)


#### Import

import pkg

~~~go
import (
    "github.com/deatil/go-datebin/datebin"
)
~~~


#### GetErrors

~~~go
// type 1
var datebinErrs []error
date := datebin.
    Now().
    OnError(func(err []error) {
        datebinErrs = err
    }).
    ToDatetimeString()

// type 2
errs := datebin.
    Parse("2022-101-23 22:18:56").
    GetErrors()

// type 3
err := datebin.
    Parse("2022-101-23 22:18:56").
    Error()
if err != nil {
    errStr := err.Error()
}
~~~


#### GetAndSetData

~~~go
// set Time
datebin.WithTime(time time.Time)
// Get Time
datebin.GetTime() time.Time
// set WeekStartAt
datebin.WithWeekStartAt(weekday time.Weekday)
// Get WeekStartAt
datebin.GetWeekStartAt() time.Weekday
// set Location
datebin.WithLocation(loc *time.Location)
// Get Location
datebin.GetLocation() *time.Location
// Get LocationString
datebin.GetLocationString() string
// Set Timezone
datebin.SetTimezone(timezone string)
// GetTimezone
datebin.GetTimezone() string
// Get Offset
datebin.GetOffset() int
// get errors
datebin.GetErrors() []error
// add error
datebin.AppendError(err ...error) Datebin
// get errors
datebin.Error() error
~~~


#### TodayAndMore

some const example
~~~go
// UTC timezone
timezone := datebin.UTC

// global set timezone
datebin.SetTimezone(timezone)

// const funcs
date := datebin.
    Now().
    // Now(timezone).
    // Today(timezone).
    // Tomorrow(timezone).
    // Yesterday(timezone).
    ToDatetimeString()
~~~


#### Input

~~~go
import (
    "time"
    "github.com/deatil/go-datebin/datebin"
)

// get timezone
timezone := datebin.UTC

// example
var datetimeString string = datebin.FromDatetime(2024, 01, 15, 23, 35, 01).ToDatetimeString()
// output: 2024-01-15 23:35:01

// from time functions
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


#### Parse

parse time

~~~go
// timezone
timezone := datebin.UTC

// example
var datetimeString string = datebin.Parse("2022-10-23 22:18:56").ToDatetimeString()

// parse time
date := datebin.
    Parse("2022-10-23 22:18:56").
    // ParseWithLayout("2022-10-23 22:18:56", "2006-01-02 15:04:05", timezone).
    // ParseWithFormat("2022-10-23 22:18:56", "Y-m-d H:i:s", timezone).
    // ParseDatetimeString("2022-10-23 22:18:56", "2006-01-02 15:04:05").
    // ParseDatetimeString("2022-10-23 22:18:56", "Y-m-d H:i:s", "u").
    ToDatetimeString()
~~~


#### Output

output time string

~~~go
// get timezone
timezone := datebin.UTC

// example
var datetimeString string = datebin.Parse("2022-10-23 22:18:56").ToDatetimeString()

// output time string
date := datebin.
    Parse("2022-10-23 22:18:56").
    // String()
    // ToString(timezone) # output string
    // ToStarString(timezone) # output Star name
    // ToSeasonString(timezone) # output Season name
    // ToWeekdayString(timezone) # output Weekday name
    // Layout("2006-01-02 15:04:05", timezone) # output datetime with layout
    // ToLayoutString("2006-01-02 15:04:05", timezone) # output datetime with layout
    // Format("Y-m-d H:i:s", timezone) # output datetime with sign
    // ToFormatString("Y-m-d H:i:s", timezone) # output datetime with sign
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
    // ToISO8601ZuluString()
    // ToRFC1036String()
    // ToRFC7231String()
    // ToAtomString()
    // ToW3CString()
    // ToDayDateTimeString()
    // ToFormattedDateString()
    // ToFormattedDayDateString()
    // ToDatetimeString()
    // ToDateString()
    // ToTimeString()
    // ToShortDatetimeString()
    // ToShortDateString()
    // ToShortTimeString()
    ToDatetimeString()
~~~


#### Helper

helper functions

~~~go
// timezone
timezone := datebin.UTC

// now time timestamp
var data int64 = datebin.NowTime(timezone)

// now Datetime string
var data string = datebin.NowDatetimeString(timezone)

// now date string
var data string = datebin.NowDateString(timezone)

// now time string
var data string = datebin.NowTimeString(timezone)

// timestamp to time.Time
var timeData time.Time = datebin.TimestampToTime(int64(1652587697), timezone)

// time.Time to timestamp
var timestampData int64 = datebin.TimeToTimestamp(timeData, timezone)

// String time To time.Time
var timeData2 time.Time = datebin.StringToTime("2022-10-23 22:18:56", "2006-01-02 15:04:05")
var timeData2 time.Time = datebin.StringToTime("2022-10-23 22:18:56", "Y-m-d H:i:s", "u")

// String time To Timestamp
var timestampData2 int64 = datebin.StringToTimestamp("2022-10-23 22:18:56", "2006-01-02 15:04:05")
var timestampData2 int64 = datebin.StringToTimestamp("2022-10-23 22:18:56", "Y-m-d H:i:s", "u")
~~~


#### Compare

Compare a and b times

~~~go
// some times
timeA := datebin.Parse("2022-10-23 22:18:56")
timeB := datebin.Parse("2022-10-25 23:18:56")
timeC := datebin.Parse("2022-10-26 23:18:56")

// timeA Gt timeB
res := timeA.Gt(timeB)

// timeA Lt timeB
res := timeA.Lt(timeB)

// timeA Eq timeB
res := timeA.Eq(timeB)

// timeA Ne timeB
res := timeA.Ne(timeB)

// timeA Gte timeB
res := timeA.Gte(timeB)

// timeA Lte timeB
res := timeA.Lte(timeB)

// Between times
res := timeA.Between(timeB, timeC)

// Between Included times
res := timeA.BetweenIncluded(timeB, timeC)

// Between Includ Start time
res := timeA.BetweenIncludStart(timeB, timeC)

// Between Includ End time
res := timeA.BetweenIncludEnd(timeB, timeC)

// Min time
res := timeA.Min(timeB)
res := timeA.Minimum(timeB)

// Max time
res := timeA.Max(timeB)
res := timeA.Maximum(timeB)

// Avg time
res := timeA.Avg(timeB)
res := timeA.Average(timeB)

// a or b is the time Closest time
res := timeA.Closest(timeB, timeC)

// a or b is the time Farthest time
res := timeA.Farthest(timeB, timeC)

// age
res := timeA.Age()

// Round time
res := timeA.Round(d time.Duration)

// Truncate time
res := timeA.Truncate(d time.Duration)
~~~


#### GetTime

get time data.

~~~go
// parse time
time := datebin.Parse("2022-10-23 22:18:56")

// get Century time
res := time.Century()

// get Decade time
res := time.Decade()

// get Year time
res := time.Year()

// get Quarter
res := time.Quarter()

// get Month
res := time.Month()

// get Weekday
res := time.Weekday()

// get Day
res := time.Day()

// get Hour
res := time.Hour()

// get Minute
res := time.Minute()

// get Second
res := time.Second()

// get Millisecond [0, 999]
res := time.Millisecond()

// get Microsecond [0, 999999]
res := time.Microsecond()

// get Nanosecond [0, 999999999]
res := time.Nanosecond()

// get Timestamp
res := time.Timestamp()
res := time.TimestampWithSecond()

// get TimestampWithMillisecond
res := time.TimestampWithMillisecond()

// get TimestampWithMicrosecond
res := time.TimestampWithMicrosecond()

// get TimestampWithNanosecond
res := time.TimestampWithNanosecond()

// get year, month, day
year, month, day := time.Date()

// get hour, minute, second
hour, minute, second := time.Time()

// get year, month, day, hour, minute, second
year, month, day, hour, minute, second := time.Datetime()

// get year, month, day, hour, minute, second, nanosecond
year, month, day, hour, minute, second, nanosecond := time.DatetimeWithNanosecond()

// get year, month, day, hour, minute, second, microsecond
year, month, day, hour, minute, second, microsecond := time.DatetimeWithMicrosecond()

// get year, month, day, hour, minute, second, millisecond
year, month, day, hour, minute, second, millisecond := time.DatetimeWithMillisecond()

// get the Month days
res := time.DaysInMonth()

// get Month Of Year
res := time.MonthOfYear()

// get Day Of Year
res := time.DayOfYear()

// get Day Of Month
res := time.DayOfMonth()

// get Day Of Week
res := time.DayOfWeek()

// get Week Of Year
res := time.WeekOfYear()
~~~


#### DiffTime

get diff data from two times

~~~go
// some times
timeA := datebin.Parse("2022-10-23 22:18:56")
timeB := datebin.Parse("2022-10-25 23:18:56")

diffTime := timeA.Diff(timeB)

// diff Seconds
data := diffTime.Seconds()

// diff Seconds abs
data := diffTime.SecondsAbs()

// others
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

// format string output
data := diffTime.Format("{Y} years ago")
data := diffTime.Format("{m} Months ago")
data := diffTime.Format("{d} Days ago")
data := diffTime.Format("{H} Hours ago")
data := diffTime.Format("{i} Minutes ago")
data := diffTime.Format("{s} Seconds ago")
data := timeA.Diff(timeB).Format("{dd} Day {HH} Hour {ii} Minute {ss} Second ago")
data := timeA.Diff(timeB).Format("{WW} week {DD} Day {HH} Hour {ii} Minute {ss} Second ago")
~~~


#### AddOrSub

some `Add` or `Sub` functions

~~~go
// some times
time := datebin.Parse("2022-10-23 22:18:56")

// Sub n Years
date := time.SubYears(uint(2)).ToDatetimeString()

// some functions
date := time.SubYears(uint(2)).
    # set year
    // SubYears(uint(2))
    // SubYearsNoOverflow(uint(2))
    // SubYear()
    // SubYearNoOverflow()

    // AddYears(uint(2))
    // AddYearsNoOverflow(uint(2))
    // AddYear()
    // AddYearNoOverflow()

    # set Month
    // SubMonths(uint(2))
    // SubMonthsNoOverflow(uint(2))
    // SubMonth()
    // SubMonthNoOverflow()

    // AddMonths(uint(2))
    // AddMonthsNoOverflow(uint(2))
    // AddMonth()
    // AddMonthNoOverflow()

    # set Weekday
    // SubWeekdays(uint(2))
    // SubWeekday()

    // AddWeekdays(uint(2))
    // AddWeekday()

    # set Day
    // SubDays(uint(2)) # sub n days
    // SubDay() # sub one day

    // AddDays(uint(2)) # add n days
    // AddDay() # add one day

    # set Hour
    // SubHours(uint(2))
    // SubHour()

    // AddHours(uint(2))
    // AddHour()

    # set Minute
    // SubMinutes(uint(2))
    // SubMinute()

    // AddMinutes(uint(2))
    // AddMinute()

    # set Second
    // SubSeconds(uint(2))
    // SubSecond()

    // AddSeconds(uint(2))
    // AddSecond()

    # Millisecond
    // SubMilliseconds(uint(2))
    // SubMillisecond()

    // AddMilliseconds(uint(2))
    // AddMillisecond()

    # Microsecond
    // SubMicroseconds(uint(2))
    // SubMicrosecond()

    // AddMicroseconds(uint(2))
    // AddMicrosecond()

    # Nanosecond
    // SubNanoseconds(uint(2))
    // SubNanosecond()

    // AddNanoseconds(uint(2))
    // AddNanosecond()

    ToDatetimeString()
~~~


#### Is

some `Is` functions

~~~go
time := datebin.Parse("2022-10-23 22:18:56")

// time Is Zero
res := time.IsZero()

// time Is Invalid
res := time.IsInvalid()

// time Is UTC timezone
res := time.IsUTC()

// time Is Local timezone
res := time.IsLocal()

// time Is Now
res := time.IsNow()

// time Is Future
res := time.IsFuture()

// time Is Past
res := time.IsPast()

// time Is LeapYear
res := time.IsLeapYear()

// time Is LongYear
res := time.IsLongYear()

// time Is Today
res := time.IsToday()

// time Is Yesterday
res := time.IsYesterday()

// time Is Tomorrow
res := time.IsTomorrow()

// time Is Current Year
res := time.IsCurrentYear()

// time Is Current Month
res := time.IsCurrentMonth()

// time Is Lately Week
res := time.IsLatelyWeek()

// time Is Lately Month
res := time.IsLatelyMonth()

// time Is LastOfMonth
res := time.IsLastOfMonth()

// time Is Start Of Day
res := time.IsStartOfDay()

// time Is StartOfDayWithMicrosecond
res := time.IsStartOfDayWithMicrosecond()

// time Is EndOfDay
res := time.IsEndOfDay()

// time Is EndOfDayWithMicrosecond
res := time.IsEndOfDayWithMicrosecond()

// time Is Midnight
res := time.IsMidnight()

// time Is Midday
res := time.IsMidday()

// time Is Spring
res := time.IsSpring()

// time Is Summer
res := time.IsSummer()

// time Is Autumn
res := time.IsAutumn()

// time Is Winter
res := time.IsWinter()
~~~


#### IsMonth

some `IsMonth` functions

~~~go
time := datebin.Parse("2022-10-23 22:18:56")

// time Is January
res := time.IsJanuary()

// time Is February
res := time.IsFebruary()

// time Is March
res := time.IsMarch()

// time Is April
res := time.IsApril()

// time Is May
res := time.IsMay()

// time Is June
res := time.IsJune()

// time Is July
res := time.IsJuly()

// time Is August
res := time.IsAugust()

// time Is September
res := time.IsSeptember()

// time Is October
res := time.IsOctober()

// time Is November
res := time.IsNovember()

// time Is December
res := time.IsDecember()
~~~


#### IsStar

some `IsStar` functions

~~~go
time := datebin.Parse("2022-10-23 22:18:56")

// time Is CapricornStar
res := time.IsCapricornStar()

// time Is AquariusStar
res := time.IsAquariusStar()

// time Is PiscesStar
res := time.IsPiscesStar()

// time Is AriesStar
res := time.IsAriesStar()

// time Is TaurusStar
res := time.IsTaurusStar()

// time Is GeminiStar
res := time.IsGeminiStar()

// time Is CancerStar
res := time.IsCancerStar()

// time Is LeoStar
res := time.IsLeoStar()

// time Is VirgoStar
res := time.IsVirgoStar()

// time Is LibraStar
res := time.IsLibraStar()

// time Is ScorpioStar
res := time.IsScorpioStar()

// time Is SagittariusStar
res := time.IsSagittariusStar()
~~~


#### IsWeek

some `IsWeek` functions

~~~go
time := datebin.Parse("2022-10-23 22:18:56")

// time Is Monday
res := time.IsMonday()

// time Is Tuesday
res := time.IsTuesday()

// time Is Wednesday
res := time.IsWednesday()

// time Is Thursday
res := time.IsThursday()

// time Is Friday
res := time.IsFriday()

// time Is Saturday
res := time.IsSaturday()

// time Is Sunday
res := time.IsSunday()

// time Is Weekday
res := time.IsWeekday()

// time Is Weekend
res := time.IsWeekend()
~~~


#### IsEqual

some `IsEqual` functions

~~~go
timeA := datebin.Parse("2022-10-23 22:18:56")
timeB := datebin.Parse("2022-10-25 23:18:56")

// for format
format := "Y-m-d H:i:s"
layout := "2006-01-02 15:04:05"
unit := "year" // year | week | day | hour | minute | second | micro | microsecond

// for string format
res := timeA.IsSameAs(format, timeB)

// for string layout
res := timeA.IsSameAsWithLayout(layout, timeB)

// for unit
res := timeA.IsSameUnit(unit, timeB)

// time Is SameYear
res := timeA.IsSameYear(timeB)

// time Is SameMonth
res := timeA.IsSameMonth(timeB)

// time Is SameDay
res := timeA.IsSameDay(timeB)

// time Is Same Hour
res := timeA.IsSameHour(timeB)

// time Is Same Minute
res := timeA.IsSameMinute(timeB)

// time Is Same Second
res := timeA.IsSameSecond(timeB)

// time Is Same YearMonth
res := timeA.IsSameYearMonth(timeB)

// time Is Same MonthDay
res := timeA.IsSameMonthDay(timeB)

// time Is Same YearMonthDay
res := timeA.IsSameYearMonthDay(timeB)

// time Is Same Birthday
res := timeA.IsSameBirthday(timeB)
~~~


#### Setting

set time data for datebin

~~~go
time := datebin.Parse("2022-10-23 22:18:56")

// datebin weeks
// datebin.Monday | datebin.Tuesday | datebin.Wednesday
// datebin.Thursday | datebin.Friday | datebin.Saturday
// datebin.Sunday
day := datebin.Monday

// set Week Start
res := time.SetWeekStartsAt(day int)

// Set Datetime With Nanosecond
res := time.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond int)

// Set Datetime With Microsecond
res := time.SetDatetimeWithMicrosecond(year, month, day, hour, minute, second, microsecond int)

// Set Datetime With Millisecond
res := time.SetDatetimeWithMillisecond(year, month, day, hour, minute, second, millisecond int)

// Set Datetime
res := time.SetDatetime(year, month, day, hour, minute, second int)

// Set Date
res := time.SetDate(year, month, day int)

// Set Time
res := time.SetTime(hour, minute, second int)

// Set Year
res := time.SetYear(year int)

// Set Month
res := time.SetMonth(month int)

// Set Day
res := time.SetDay(day int)

// Set Hour
res := time.SetHour(hour int)

// Set Minute
res := time.SetMinute(minute int)

// Set Second
res := time.SetSecond(second int)

// Set Millisecond
res := time.SetMillisecond(millisecond int)

// Set Microsecond
res := time.SetMicrosecond(microsecond int)

// Set Nanosecond
res := time.SetNanosecond(nanosecond int)

// output Datetime String
date := res.ToDatetimeString()
~~~


#### GetBetween

get Between time data

~~~go
// YearStart
res := datebin.Parse("2022-10-23 22:18:56").YearStart().ToDatetimeString()

// some functions
res := datebin.Parse("2022-10-23 22:18:56").
    NYearStart(2). # n years start
    // NYearEnd(2). # n years end
    // CenturyStart(). # a century years start
    // CenturyEnd(). # a century years end
    // DecadeStart(). # a decade years start
    // DecadeEnd(). # a decade years end
    // YearStart(). # year start
    // YearEnd(). # year end
    // SeasonStart(). # season start
    // SeasonEnd(). # season end
    // MonthStart(). # month start
    // MonthEnd(). # month end
    // WeekStart(). # week start
    // WeekEnd(). # week end
    // DayStart(). # day start
    // DayEnd(). # day end
    // HourStart(). # hour start
    // HourEnd(). # hour end
    // MinuteStart(). # minute start
    // MinuteEnd(). # minute end
    // SecondStart(). # second start
    // SecondEnd(). # second end
    ToDatetimeString()
~~~

#### Datetimes

get some data from two times.

~~~go
import (
    "github.com/deatil/go-datebin/datetimes"
)

start := datebin.Parse("2022-10-23 22:18:56")
end := datebin.Parse("2023-10-23 22:18:56")

d1 := datetimes.New(start, end)
d2 := datetimes.New(start1, end1)

// get Intersection times
var res Datetimes = d1.Intersection(d2)

// get Union times
var res []Datetimes = d1.Union(d2)

// if d1 Is Contain d2
var res bool = d1.IsContain(d2)

// get times Length
var res int64 = d1.Length()

// get times Length With Nanosecond
var res int64 = d1.LengthWithNanosecond()

// if d1 Gt d2
var res bool = d1.Gt(d2)

// if d1 Lt d2
var res bool = d1.Lt(d2)

// if d1 Eq d2
var res bool = d1.Eq(d2)

// if d1 not eq d2
var res bool = d1.Ne(d2)

// if d1 Gte d2
var res bool = d1.Gte(d2)

// if d1 Lte d2
var res bool = d1.Lte(d2)
~~~


#### FormatWithSign

| sign | desc |  length | range | example |
| :------------: | :------------: | :------------: | :------------: | :------------: |
| c | ISO8601 format | - | - | 2006-01-02T15:04:05-07:00 |
| r | RFC2822 format | - | - | Mon, 02 Jan 2006 15:04:05 -0700 |
| Y | Four-digit year | 4 | 0000-9999 | 2016 |
| y | Two-digit year | 2 | 00-99 | 07 |
| m | Month, padded to 2 | 2 | 01-12 | 01 |
| M | Month as an abbreviated localized string | 3 | Jan-Dec | Dec |
| n | Month, no padding | - | 1-12 | 2 |
| d | Day of the month, padded to 2 | 2 | 01-31 | 05 |
| D | Day of the week, as an abbreviate localized string | 3 | Mon-Sun | Mon |
| j | Day of the month, no padding | - |1-31 | 2 |
| h | Hour in 12-hour format, padded to 2 | 2 | 00-11 | 03 |
| H | Hour in 24-hour format, padded to 2 | 2 | 00-23 | 15 |
| g | Hour in 12-hour format, no padding | - | 1-12 | 3 |
| G | Hour in 24-hour format, no padding | - | 0-23 | 15 |
| i | Minute, padded to 2 | 2 | 01-59 | 04 |
| s | Second, padded to 2 | 2 | 01-59 | 05 |
| a | Lowercase morning or afternoon sign | 2 | am/pm | pm |
| A | Uppercase morning or afternoon sign | 2 | AM/PM | AM |
| e | Location | - | - | America/New_York |
| S | English ordinal suffix for the day of the month, 2 characters. Eg: st, nd, rd or th. Works well with j | 2 | st/nd/rd/th | rd |
| l | Day of the week, as an unabbreviated localized string | - | Monday-Sunday | Monday |
| F | Month as an unabbreviated localized string | - | January-December | January |
| O | Difference to Greenwich time (GMT) without colon between hours and minutes | - | - | -0700 |
| P | Difference to Greenwich time (GMT) with colon between hours and minutes | - | - | +07:00 |
| T | Abbreviated timezone | - | - | MST |
| W | week of the year | - | 1-52 | 1 |
| N | day of the week | 1 | 1-7 | 1 |
| L | Whether it's a leap year | - | ly/nly | nly |
| U | Unix timestamp with seconds | 10 | - | 1611818268 |
| u | Microsecond | 6 | 000000-999999 | 111999 |
| w | Day of the week | 1 | 0-6 | 1 |
| t | Total days of the month | 2 | 28-31 | 29 |
| z | Day of the year | - | 0-365 | 3 |
| Q | Quarter | 1 | 1-4 | 2 |
| C | Century | - | 0-99 | 22 |
