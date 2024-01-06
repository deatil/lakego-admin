package datebin

import (
    "time"
)

// 设置一周的开始日期
func (this Datebin) SetWeekStartsAt(day string) Datebin {
    switch day {
        case Monday:
            this.weekStartAt = time.Monday
        case Tuesday:
            this.weekStartAt = time.Tuesday
        case Wednesday:
            this.weekStartAt = time.Wednesday
        case Thursday:
            this.weekStartAt = time.Thursday
        case Friday:
            this.weekStartAt = time.Friday
        case Saturday:
            this.weekStartAt = time.Saturday
        case Sunday:
            this.weekStartAt = time.Sunday
    }

    return this
}

// 日期时间带纳秒
func (this Datebin) SetDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond int) Datebin {
    this.time = time.Date(year, time.Month(month), day, hour, minute, second, nanosecond, this.loc)
    return this
}

// 日期时间带微秒
func (this Datebin) SetDatetimeWithMicrosecond(year, month, day, hour, minute, second, microsecond int) Datebin {
    nanosecond := microsecond * 1e3

    return this.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond)
}

// 日期时间带毫秒
func (this Datebin) SetDatetimeWithMillisecond(year, month, day, hour, minute, second, millisecond int) Datebin {
    nanosecond := millisecond * 1e6

    return this.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond)
}

// 日期时间
func (this Datebin) SetDatetime(year, month, day, hour, minute, second int) Datebin {
    nanosecond := this.Nanosecond()

    return this.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond)
}

// 日期
func (this Datebin) SetDate(year, month, day int) Datebin {
    hour, minute, second := this.Time()
    nanosecond := this.Nanosecond()

    return this.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond)
}

// 时间
func (this Datebin) SetTime(hour, minute, second int) Datebin {
    year, month, day := this.Date()
    nanosecond := this.Nanosecond()

    return this.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond)
}

// 设置年份
func (this Datebin) SetYear(year int) Datebin {
    _, month, day, hour, minute, second, nanosecond := this.DatetimeWithNanosecond()

    return this.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond)
}

// 设置月份
func (this Datebin) SetMonth(month int) Datebin {
    year, _, day, hour, minute, second, nanosecond := this.DatetimeWithNanosecond()

    return this.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond)
}

// 设置天
func (this Datebin) SetDay(day int) Datebin {
    year, month, _, hour, minute, second, nanosecond := this.DatetimeWithNanosecond()

    return this.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond)
}

// 设置小时
func (this Datebin) SetHour(hour int) Datebin {
    year, month, day, _, minute, second, nanosecond := this.DatetimeWithNanosecond()

    return this.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond)
}

// 设置分钟
func (this Datebin) SetMinute(minute int) Datebin {
    year, month, day, hour, _, second, nanosecond := this.DatetimeWithNanosecond()

    return this.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond)
}

// 设置秒数
func (this Datebin) SetSecond(second int) Datebin {
    year, month, day, hour, minute, _, nanosecond := this.DatetimeWithNanosecond()

    return this.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond)
}

// 设置毫秒
func (this Datebin) SetMillisecond(millisecond int) Datebin {
    year, month, day, hour, minute, second := this.Datetime()
    nanosecond := millisecond*1e6

    return this.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond)
}

// 设置微秒
func (this Datebin) SetMicrosecond(microsecond int) Datebin {
    year, month, day, hour, minute, second := this.Datetime()
    nanosecond := microsecond*1e3

    return this.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond)
}

// 设置纳秒
func (this Datebin) SetNanosecond(nanosecond int) Datebin {
    year, month, day, hour, minute, second := this.Datetime()

    return this.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond)
}

