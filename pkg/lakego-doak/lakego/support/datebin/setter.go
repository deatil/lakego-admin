package datebin

import (
    "time"
)

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

