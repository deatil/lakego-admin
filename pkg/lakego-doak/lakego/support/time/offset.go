package time

import (
    "time"
    "strings"
)

// 间隔
func (this Datebin) Offset(field string, offset int, timezone ...string) Datebin {
    if len(timezone) > 0 {
        this.loc, this.Error = this.GetLocationByTimezone(timezone[0])
    }

    if this.Error != nil {
        return this
    }

    // 设置时区
    this.time = this.time.In(this.loc)

    field = strings.ToLower(field)

    // 相关匹配
    switch field {
        // 百年
        case "century":
            offset = offset * YearsPerCentury
            this.time = this.time.AddDate(offset, 0, 0)
        // 十年
        case "decade":
            offset = offset * YearsPerDecade
            this.time = this.time.AddDate(offset, 0, 0)
        // 一年
        case "year":
            this.time = this.time.AddDate(offset, 0, 0)
        // 季度
        case "quarter":
            offset = offset * MonthsPerQuarter
            this.time = this.time.AddDate(0, offset, 0)
        // 一个月
        case "month":
            this.time = this.time.AddDate(0, offset, 0)
        // 一周
        case "weekday":
            offset = offset * DaysPerWeek
            this.time = this.time.AddDate(0, 0, offset)
        // 一天
        case "day":
            this.time = this.time.AddDate(0, 0, offset)
        // 一小时
        case "hour":
            this.time = this.time.Add(time.Hour * time.Duration(offset))
        // 一分钟
        case "minute":
            this.time = this.time.Add(time.Minute * time.Duration(offset))
        // 一秒
        case "second":
            this.time = this.time.Add(time.Second * time.Duration(offset))
        // 毫秒
        case "millisecond", "milli":
            this.time = this.time.Add(time.Millisecond * time.Duration(offset))
        // 微妙
        case "microsecond", "micro":
            this.time = this.time.Add(time.Microsecond * time.Duration(offset))
        // 纳秒
        case "nanosecond", "nano":
            this.time = this.time.Add(time.Nanosecond * time.Duration(offset))
        // 默认不处理
        default:
    }

    return this
}

// 不溢出增加/减少 n 年
func (this Datebin) OffsetYearsNoOverflow(years int) Datebin {
    if this.IsInvalid() {
        return this
    }

    // N年后本月的最后一天
    last := time.Date(this.Year() + years, time.Month(this.Month()), 1, this.Hour(), this.Minute(), this.Second(), this.Nanosecond(), this.loc).AddDate(0, 1, -1)
    day := this.Day()
    if this.Day() > last.Day() {
        day = last.Day()
    }

    this.time = time.Date(last.Year(), last.Month(), day, this.Hour(), this.Minute(), this.Second(), this.Nanosecond(), this.loc)
    return this
}

// 不溢出增加/减少 n 月
func (this Datebin) OffsetMonthsNoOverflow(months int) Datebin {
    if this.IsInvalid() {
        return this
    }

    month := this.Month() + months

    // n+1月第一天减一天
    last := time.Date(this.Year(), time.Month(month), 1, this.Hour(), this.Minute(), this.Second(), this.Nanosecond(), this.loc).AddDate(0, 1, -1)
    day := this.Day()
    if this.Day() > last.Day() {
        day = last.Day()
    }

    this.time = time.Date(last.Year(), last.Month(), day, this.Hour(), this.Minute(), this.Second(), this.Nanosecond(), this.loc)
    return this
}

// 按照持续时长字符串增加时间
func (this Datebin) AddDuration(duration string) Datebin {
    if this.IsInvalid() {
        return this
    }

    td, err := this.ParseDuration(duration)
    this.time = this.time.In(this.loc).Add(td)
    this.Error = err
    return this
}

// 按照持续时长字符串减少时间
func (this Datebin) SubDuration(duration string) Datebin {
    return this.AddDuration("-" + duration)
}

// 前 n 百年
func (this Datebin) SubCenturies(data uint) Datebin {
    offset := 0 - int(data)

    return this.Offset("century", offset)
}

// 前 n 百年
func (this Datebin) SubCenturiesNoOverflow(data uint) Datebin {
    offset := 0 - int(data)

    return this.OffsetYearsNoOverflow(offset * YearsPerCentury)
}

// 前一百年
func (this Datebin) SubCentury() Datebin {
    return this.SubCenturies(1)
}

// 前一百年
func (this Datebin) SubCenturyNoOverflow() Datebin {
    return this.SubCenturiesNoOverflow(1)
}

// 后 n 百年
func (this Datebin) AddCenturies(data uint) Datebin {
    return this.Offset("century", int(data))
}

// 后 n 百年
func (this Datebin) AddCenturiesNoOverflow(data uint) Datebin {
    return this.OffsetYearsNoOverflow(int(data) * YearsPerCentury)
}

// 后一百年
func (this Datebin) AddCentury() Datebin {
    return this.AddCenturies(1)
}

// 后一百年
func (this Datebin) AddCenturyNoOverflow() Datebin {
    return this.AddCenturiesNoOverflow(1)
}

// 前 n 十年
func (this Datebin) SubDecades(data uint) Datebin {
    offset := 0 - int(data)

    return this.Offset("decade", offset)
}

// 前 n 十年
func (this Datebin) SubDecadesNoOverflow(data uint) Datebin {
    offset := 0 - int(data)

    return this.OffsetYearsNoOverflow(offset * YearsPerDecade)
}

// 前十年
func (this Datebin) SubDecade() Datebin {
    return this.SubDecades(1)
}

// 前十年
func (this Datebin) SubDecadeNoOverflow() Datebin {
    return this.SubDecadesNoOverflow(1)
}

// 后 n 十年
func (this Datebin) AddDecades(data uint) Datebin {
    return this.Offset("decade", int(data))
}

// 后 n 十年
func (this Datebin) AddDecadesNoOverflow(data uint) Datebin {
    return this.OffsetYearsNoOverflow(int(data) * YearsPerDecade)
}

// 后十年
func (this Datebin) AddDecade() Datebin {
    return this.AddDecades(1)
}

// 后十年
func (this Datebin) AddDecadeNoOverflow() Datebin {
    return this.AddDecadesNoOverflow(1)
}

// 前 n 年
func (this Datebin) SubYears(data uint) Datebin {
    offset := 0 - int(data)

    return this.Offset("year", offset)
}

// 前 n 年
func (this Datebin) SubYearsNoOverflow(data uint) Datebin {
    offset := 0 - int(data)

    return this.OffsetYearsNoOverflow(offset)
}

// 前一年
func (this Datebin) SubYear() Datebin {
    return this.SubYears(1)
}

// 前一年
func (this Datebin) SubYearNoOverflow() Datebin {
    return this.SubYearsNoOverflow(1)
}

// 后 n 年
func (this Datebin) AddYears(data uint) Datebin {
    return this.Offset("year", int(data))
}

// 后 n 年 (月份不溢出)
func (this Datebin) AddYearsNoOverflow(years uint) Datebin {
    return this.OffsetYearsNoOverflow(int(years))
}

// 后一年
func (this Datebin) AddYear() Datebin {
    return this.AddYears(1)
}

// 后一年
func (this Datebin) AddYearNoOverflow() Datebin {
    return this.AddYearsNoOverflow(1)
}

// 前 n 季度
func (this Datebin) SubQuarters(data uint) Datebin {
    offset := 0 - int(data)

    return this.Offset("quarter", offset)
}

// 前 n 季度
func (this Datebin) SubQuartersNoOverflow(data uint) Datebin {
    offset := 0 - int(data)

    return this.OffsetMonthsNoOverflow(offset * MonthsPerQuarter)
}

// 前一季度
func (this Datebin) SubQuarter() Datebin {
    return this.SubQuarters(1)
}

// 前一季度
func (this Datebin) SubQuarterNoOverflow() Datebin {
    return this.SubQuartersNoOverflow(1)
}

// 后 n 季度
func (this Datebin) AddQuarters(data uint) Datebin {
    return this.Offset("quarter", int(data))
}

// 后 n 季度
func (this Datebin) AddQuartersNoOverflow(data uint) Datebin {
    return this.OffsetMonthsNoOverflow(int(data) * MonthsPerQuarter)
}

// 后一季度
func (this Datebin) AddQuarter() Datebin {
    return this.AddQuarters(1)
}

// 后一季度
func (this Datebin) AddQuarterNoOverflow() Datebin {
    return this.AddQuartersNoOverflow(1)
}

// 前 n 月
func (this Datebin) SubMonths(data uint) Datebin {
    offset := 0 - int(data)

    return this.Offset("month", offset)
}

// 前 n 月
func (this Datebin) SubMonthsNoOverflow(data uint) Datebin {
    offset := 0 - int(data)

    return this.OffsetMonthsNoOverflow(offset)
}

// 前一月
func (this Datebin) SubMonth() Datebin {
    return this.SubMonths(1)
}

// 前一月
func (this Datebin) SubMonthNoOverflow() Datebin {
    return this.SubMonthsNoOverflow(1)
}

// 后 n 月
func (this Datebin) AddMonths(data uint) Datebin {
    return this.Offset("month", int(data))
}

// 后 n 月 (月份不溢出)
func (this Datebin) AddMonthsNoOverflow(months uint) Datebin {
    return this.OffsetMonthsNoOverflow(int(months))
}

// 后一月
func (this Datebin) AddMonth() Datebin {
    return this.AddMonths(1)
}

// 后一月
func (this Datebin) AddMonthNoOverflow() Datebin {
    return this.AddMonthsNoOverflow(1)
}

// 前 n 周
func (this Datebin) SubWeekdays(data uint) Datebin {
    offset := 0 - int(data)

    return this.Offset("weekday", offset)
}

// 前一周
func (this Datebin) SubWeekday() Datebin {
    return this.SubWeekdays(1)
}

// 后 n 周
func (this Datebin) AddWeekdays(data uint) Datebin {
    return this.Offset("weekday", int(data))
}

// 后一周
func (this Datebin) AddWeekday() Datebin {
    return this.AddWeekdays(1)
}

// 前 n 天
func (this Datebin) SubDays(data uint) Datebin {
    offset := 0 - int(data)

    return this.Offset("day", offset)
}

// 前一天
func (this Datebin) SubDay() Datebin {
    return this.SubDays(1)
}

// 后 n 天
func (this Datebin) AddDays(data uint) Datebin {
    return this.Offset("day", int(data))
}

// 后一天
func (this Datebin) AddDay() Datebin {
    return this.AddDays(1)
}

// 前 n 小时
func (this Datebin) SubHours(data uint) Datebin {
    offset := 0 - int(data)

    return this.Offset("hour", offset)
}

// 前一小时
func (this Datebin) SubHour() Datebin {
    return this.SubHours(1)
}

// 后 n 小时
func (this Datebin) AddHours(data uint) Datebin {
    return this.Offset("hour", int(data))
}

// 后一小时
func (this Datebin) AddHour() Datebin {
    return this.AddHours(1)
}

// 前 n 分钟
func (this Datebin) SubMinutes(data uint) Datebin {
    offset := 0 - int(data)

    return this.Offset("minute", offset)
}

// 前一分钟
func (this Datebin) SubMinute() Datebin {
    return this.SubMinutes(1)
}

// 后 n 分钟
func (this Datebin) AddMinutes(data uint) Datebin {
    return this.Offset("minute", int(data))
}

// 后 n 分钟
func (this Datebin) AddMinute() Datebin {
    return this.AddMinutes(1)
}

// 前 n 秒
func (this Datebin) SubSeconds(data uint) Datebin {
    offset := 0 - int(data)

    return this.Offset("second", offset)
}

// 前一秒
func (this Datebin) SubSecond() Datebin {
    return this.SubSeconds(1)
}

// 后 n 一秒
func (this Datebin) AddSeconds(data uint) Datebin {
    return this.Offset("second", int(data))
}

// 后一秒
func (this Datebin) AddSecond() Datebin {
    return this.AddSeconds(1)
}

// 前 n 毫秒
func (this Datebin) SubMilliseconds(data uint) Datebin {
    offset := 0 - int(data)

    return this.Offset("millisecond", offset)
}

// 前一毫秒
func (this Datebin) SubMillisecond() Datebin {
    return this.SubMilliseconds(1)
}

// 后 n 毫秒
func (this Datebin) AddMilliseconds(data uint) Datebin {
    return this.Offset("millisecond", int(data))
}

// 后一毫秒
func (this Datebin) AddMillisecond() Datebin {
    return this.AddMilliseconds(1)
}

// 前 n 微妙
func (this Datebin) SubMicroseconds(data uint) Datebin {
    offset := 0 - int(data)

    return this.Offset("microsecond", offset)
}

// 前一微妙
func (this Datebin) SubMicrosecond() Datebin {
    return this.SubMicroseconds(1)
}

// 后 n 微妙
func (this Datebin) AddMicroseconds(data uint) Datebin {
    return this.Offset("microsecond", int(data))
}

// 后一微妙
func (this Datebin) AddMicrosecond() Datebin {
    return this.AddMicroseconds(1)
}

// 前 n 纳秒
func (this Datebin) SubNanoseconds(data uint) Datebin {
    offset := 0 - int(data)

    return this.Offset("nanosecond", offset)
}

// 前一纳秒
func (this Datebin) SubNanosecond() Datebin {
    return this.SubNanoseconds(1)
}

// 后 n 纳秒
func (this Datebin) AddNanoseconds(data uint) Datebin {
    return this.Offset("nanosecond", int(data))
}

// 后一纳秒
func (this Datebin) AddNanosecond() Datebin {
    return this.AddNanoseconds(1)
}
