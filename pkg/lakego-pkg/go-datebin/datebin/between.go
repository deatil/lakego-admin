package datebin

import (
    "time"
)

// 当前n年开始
func (this Datebin) NYearStart(year int) Datebin {
    if this.IsInvalid() {
        return this
    }

    if year < 0 {
        year = 0
    }

    date := (this.Year() / year) * year

    this.time = time.Date(date, 1, 1, 0, 0, 0, 0, this.loc)
    return this
}

// 当前n年结束
func (this Datebin) NYearEnd(year int) Datebin {
    if this.IsInvalid() {
        return this
    }

    if year < 0 {
        year = 0
    }

    date := (this.Year() / year) * year + (year - 1)

    this.time = time.Date(date, 12, 31, 23, 59, 59, 999999999, this.loc)
    return this
}

// 当前百年开始
func (this Datebin) CenturyStart() Datebin {
    if this.IsInvalid() {
        return this
    }

    date := (this.Year() / YearsPerCentury) * YearsPerCentury

    this.time = time.Date(date, 1, 1, 0, 0, 0, 0, this.loc)
    return this
}

// 当前百年结束
func (this Datebin) CenturyEnd() Datebin {
    if this.IsInvalid() {
        return this
    }

    date := (this.Year() / YearsPerCentury) * YearsPerCentury + 99

    this.time = time.Date(date, 12, 31, 23, 59, 59, 999999999, this.loc)
    return this
}

// 当前十年开始
func (this Datebin) DecadeStart() Datebin {
    if this.IsInvalid() {
        return this
    }

    date := (this.Year() / YearsPerDecade) * YearsPerDecade

    this.time = time.Date(date, 1, 1, 0, 0, 0, 0, this.loc)
    return this
}

// 当前十年结束
func (this Datebin) DecadeEnd() Datebin {
    if this.IsInvalid() {
        return this
    }

    date := (this.Year() / YearsPerDecade) * YearsPerDecade + 9

    this.time = time.Date(date, 12, 31, 23, 59, 59, 999999999, this.loc)
    return this
}

// 本年开始
func (this Datebin) YearStart() Datebin {
    if this.IsInvalid() {
        return this
    }

    date := this.Year()

    this.time = time.Date(date, 1, 1, 0, 0, 0, 0, this.loc)
    return this
}

// 本年结束
func (this Datebin) YearEnd() Datebin {
    if this.IsInvalid() {
        return this
    }

    date := this.Year()

    this.time = time.Date(date, 12, 31, 23, 59, 59, 999999999, this.loc)
    return this
}

// 本季节开始时间
func (this Datebin) SeasonStart() Datebin {
    if this.IsInvalid() {
        return this
    }

    if this.Month() == 1 || this.Month() == 2 {
        this.time = time.Date(this.Year() - 1, time.Month(12), 1, 0, 0, 0, 0, this.loc)
        return this
    }

    // 当年开始月份
    month := time.Month((this.Month() / 3) * 3)

    this.time = time.Date(this.Year(), month, 1, 0, 0, 0, 0, this.loc)
    return this
}

// 本季节结束时间
func (this Datebin) SeasonEnd() Datebin {
    if this.IsInvalid() {
        return this
    }

    month := this.Month()

    if month == 12 {
        this.time = time.Date(this.Year() + 1, time.Month(2), 1, 23, 59, 59, 999999999, this.loc).AddDate(0, 1, -1)
        return this
    }

    this.time = time.Date(this.Year(), time.Month((month/3)*3+2), 1, 23, 59, 59, 999999999, this.loc).AddDate(0, 1, -1)
    return this
}

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

// 本周开始
func (this Datebin) WeekStart() Datebin {
    if this.IsInvalid() {
        return this
    }

    dayOfWeek := this.DayOfWeek()
    weekStartAt := int(this.weekStartAt)

    days := (DaysPerWeek + dayOfWeek - weekStartAt) % DaysPerWeek

    return this.SubDays(uint(days)).DayStart()
}

// 本周结束
func (this Datebin) WeekEnd() Datebin {
    if this.IsInvalid() {
        return this
    }

    dayOfWeek := this.DayOfWeek()
    weekEndsAt := int(this.weekStartAt) + DaysPerWeek - 1

    days := (DaysPerWeek - dayOfWeek + weekEndsAt) % DaysPerWeek

    return this.AddDays(uint(days)).DayEnd()
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
