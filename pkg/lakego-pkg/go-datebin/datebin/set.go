package datebin

import (
    "time"
)

// 设置一周的开始日期
func (this Datebin) SetWeekStartsAt(day string) Datebin {
    if this.IsInvalid() {
        return this
    }

    // 判断周几
    switch day {
        case WeekMonday:
            this.weekStartAt = time.Monday
        case WeekTuesday:
            this.weekStartAt = time.Tuesday
        case WeekWednesday:
            this.weekStartAt = time.Wednesday
        case WeekThursday:
            this.weekStartAt = time.Thursday
        case WeekFriday:
            this.weekStartAt = time.Friday
        case WeekSaturday:
            this.weekStartAt = time.Saturday
        case WeekSunday:
            this.weekStartAt = time.Sunday
    }

    return this
}

// 设置年份
func (this Datebin) SetYear(year int) Datebin {
    if this.IsInvalid() {
        return this
    }

    this.time = time.Date(year, time.Month(this.Month()), this.Day(), this.Hour(), this.Minute(), this.Second(), this.Nanosecond(), this.loc)
    return this
}

// 设置月份
func (this Datebin) SetMonth(month int) Datebin {
    if this.IsInvalid() {
        return this
    }

    this.time = time.Date(this.Year(), time.Month(month), this.Day(), this.Hour(), this.Minute(), this.Second(), this.Nanosecond(), this.loc)
    return this
}

// 设置日期
func (this Datebin) SetDay(day int) Datebin {
    if this.IsInvalid() {
        return this
    }

    this.time = time.Date(this.Year(), time.Month(this.Month()), day, this.Hour(), this.Minute(), this.Second(), this.Nanosecond(), this.loc)
    return this
}

// 设置小时
func (this Datebin) SetHour(hour int) Datebin {
    if this.IsInvalid() {
        return this
    }

    this.time = time.Date(this.Year(), time.Month(this.Month()), this.Day(), hour, this.Minute(), this.Second(), this.Nanosecond(), this.loc)
    return this
}

// 设置分钟
func (this Datebin) SetMinute(minute int) Datebin {
    if this.IsInvalid() {
        return this
    }

    this.time = time.Date(this.Year(), time.Month(this.Month()), this.Day(), this.Hour(), minute, this.Second(), this.Nanosecond(), this.loc)
    return this
}

// 设置秒数
func (this Datebin) SetSecond(second int) Datebin {
    if this.IsInvalid() {
        return this
    }

    this.time = time.Date(this.Year(), time.Month(this.Month()), this.Day(), this.Hour(), this.Minute(), second, this.Nanosecond(), this.loc)
    return this
}

// 设置毫秒
func (this Datebin) SetMillisecond(millisecond int) Datebin {
    if this.IsInvalid() {
        return this
    }

    this.time = time.Date(this.Year(), time.Month(this.Month()), this.Day(), this.Hour(), this.Minute(), this.Second(), millisecond*1e6, this.loc)
    return this
}

// 设置微秒
func (this Datebin) SetMicrosecond(microsecond int) Datebin {
    if this.IsInvalid() {
        return this
    }

    this.time = time.Date(this.Year(), time.Month(this.Month()), this.Day(), this.Hour(), this.Minute(), this.Second(), microsecond*1e3, this.loc)
    return this
}

// 设置纳秒
func (this Datebin) SetNanosecond(nanosecond int) Datebin {
    if this.IsInvalid() {
        return this
    }

    this.time = time.Date(this.Year(), time.Month(this.Month()), this.Day(), this.Hour(), this.Minute(), this.Second(), nanosecond, this.loc)
    return this
}

// 日期时间带纳秒
func (this Datebin) SetDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond int) Datebin {
    if this.IsInvalid() {
        return this
    }

    this.time = time.Date(year, time.Month(month), day, hour, minute, second, nanosecond, this.loc)
    return this
}

// 日期时间带微秒
func (this Datebin) SetDatetimeWithMicrosecond(year, month, day, hour, minute, second, microsecond int) Datebin {
    return this.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, microsecond * 1e3)
}

// 日期时间带毫秒
func (this Datebin) SetDatetimeWithMillisecond(year, month, day, hour, minute, second, millisecond int) Datebin {
    return this.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, millisecond * 1e6)
}

// 日期时间
func (this Datebin) SetDatetime(year, month, day, hour, minute, second int) Datebin {
    return this.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, this.Nanosecond())
}

// 日期
func (this Datebin) SetDate(year, month, day int) Datebin {
    return this.SetDatetimeWithNanosecond(year, month, day, this.Hour(), this.Minute(), this.Second(), this.Nanosecond())
}

// 时间
func (this Datebin) SetTime(hour, minute, second int) Datebin {
    year, month, day := this.Date()

    return this.SetDatetimeWithNanosecond(year, month, day, hour, minute, second, this.Nanosecond())
}

