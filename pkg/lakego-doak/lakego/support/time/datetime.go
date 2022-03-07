package time

import (
    "time"
)

// 本月开始时间
func (this Datebin) MonthStart() Datebin {
    if this.IsInvalid() {
        return this
    }

    this.time = time.Date(this.Year(), time.Month(this.Month()), 1, 0, 0, 0, 0, this.loc)
    return this
}

// 本月结束时间
func (this Datebin) MonthEnd() Datebin {
    if this.IsInvalid() {
        return this
    }

    this.time = time.Date(this.Year(), time.Month(this.Month()), 1, 23, 59, 59, 999999999, this.loc).AddDate(0, 1, -1)
    return this
}

// 本日开始时间
func (this Datebin) DayStart() Datebin {
    if this.IsInvalid() {
        return this
    }

    this.time = time.Date(this.Year(), time.Month(this.Month()), this.Day(), 0, 0, 0, 0, this.loc)
    return this
}

// 本日结束时间
func (this Datebin) DayEnd() Datebin {
    if this.IsInvalid() {
        return this
    }

    this.time = time.Date(this.Year(), time.Month(this.Month()), this.Day(), 23, 59, 59, 999999999, this.loc)
    return this
}

// 小时开始时间
func (this Datebin) HourStart() Datebin {
    if this.IsInvalid() {
        return this
    }

    this.time = time.Date(this.Year(), time.Month(this.Month()), this.Day(), this.Hour(), 0, 0, 0, this.loc)
    return this
}

// 小时结束时间
func (this Datebin) HourEnd() Datebin {
    if this.IsInvalid() {
        return this
    }

    this.time = time.Date(this.Year(), time.Month(this.Month()), this.Day(), this.Hour(), 59, 59, 999999999, this.loc)
    return this
}

// 分钟开始时间
func (this Datebin) MinuteStart() Datebin {
    if this.IsInvalid() {
        return this
    }

    this.time = time.Date(this.Year(), time.Month(this.Month()), this.Day(), this.Hour(), this.Minute(), 0, 0, this.loc)
    return this
}

// 分钟结束时间
func (this Datebin) MinuteEnd() Datebin {
    if this.IsInvalid() {
        return this
    }

    this.time = time.Date(this.Year(), time.Month(this.Month()), this.Day(), this.Hour(), this.Minute(), 59, 999999999, this.loc)
    return this
}

// 秒开始时间
func (this Datebin) SecondStart() Datebin {
    if this.IsInvalid() {
        return this
    }

    this.time = time.Date(this.Year(), time.Month(this.Month()), this.Day(), this.Hour(), this.Minute(), this.Second(), 0, this.loc)
    return this
}

// 秒结束时间
func (this Datebin) SecondEnd() Datebin {
    if this.IsInvalid() {
        return this
    }

    this.time = time.Date(this.Year(), time.Month(this.Month()), this.Day(), this.Hour(), this.Minute(), this.Second(), 999999999, this.loc)
    return this
}
