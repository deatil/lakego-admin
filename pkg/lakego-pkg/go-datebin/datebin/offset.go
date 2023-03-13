package datebin

import (
    "time"
    "strings"
)

// 间隔
func (this Datebin) Offset(field string, offset int, timezone ...string) Datebin {
    if len(timezone) > 0 {
        loc, error := this.GetLocationByTimezone(timezone[0])
        if error == nil {
            this.loc = loc
        }

        this.AppendError(error)
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
    td, err := this.ParseDuration(duration)
    this.time = this.time.In(this.loc).Add(td)
    this.AppendError(err)

    return this
}

// 按照持续时长字符串减少时间
func (this Datebin) SubDuration(duration string) Datebin {
    return this.AddDuration("-" + duration)
}
