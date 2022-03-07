package time

import (
    "time"
)

// 是否是零值时间
func (this Datebin) IsZero() bool {
    return this.time.IsZero()
}

// 是否是无效时间
func (this Datebin) IsInvalid() bool {
    if this.Error != nil || this.IsZero() {
        return true
    }

    return false
}

// 是否是当前时间
func (this Datebin) IsNow() bool {
    if this.IsInvalid() {
        return false
    }

    return this.Timestamp() == this.Now().Timestamp()
}

// 是否是未来时间
func (this Datebin) IsFuture() bool {
    if this.IsInvalid() {
        return false
    }

    return this.Timestamp() > this.Now().Timestamp()
}

// 是否是过去时间
func (this Datebin) IsPast() bool {
    if this.IsInvalid() {
        return false
    }

    return this.Timestamp() < this.Now().Timestamp()
}

// 是否是闰年
func (this Datebin) IsLeapYear() bool {
    if this.IsInvalid() {
        return false
    }

    year := this.time.In(this.loc).Year()
    if year%400 == 0 || (year%4 == 0 && year%100 != 0) {
        return true
    }

    return false
}

// 是否是长年
func (this Datebin) IsLongYear() bool {
    if this.IsInvalid() {
        return false
    }

    _, w := time.Date(this.Year(), time.December, 31, 0, 0, 0, 0, this.loc).ISOWeek()
    return w == weeksPerLongYear
}

// 是否是一月
func (this Datebin) IsJanuary() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.January
}

// 是否是二月
func (this Datebin) IsFebruary() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.February
}

// 是否是三月
func (this Datebin) IsMarch() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.March
}

// 是否是四月
func (this Datebin) IsApril() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.April
}

// 是否是五月
func (this Datebin) IsMay() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.May
}

// 是否是六月
func (this Datebin) IsJune() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.June
}

// 是否是七月
func (this Datebin) IsJuly() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.July
}

// 是否是八月
func (this Datebin) IsAugust() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.August
}

// 是否是九月
func (this Datebin) IsSeptember() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.September
}

// 是否是十月
func (this Datebin) IsOctober() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.October
}

// 是否是十一月
func (this Datebin) IsNovember() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.November
}

// 是否是十二月
func (this Datebin) IsDecember() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.December
}

// 是否是周一
func (this Datebin) IsMonday() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Weekday() == time.Monday
}

// 是否是周二
func (this Datebin) IsTuesday() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Weekday() == time.Tuesday
}

// 是否是周三
func (this Datebin) IsWednesday() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Weekday() == time.Wednesday
}

// 是否是周四
func (this Datebin) IsThursday() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Weekday() == time.Thursday
}

// 是否是周五
func (this Datebin) IsFriday() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Weekday() == time.Friday
}

// 是否是周六
func (this Datebin) IsSaturday() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Weekday() == time.Saturday
}

// 是否是周日
func (this Datebin) IsSunday() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Weekday() == time.Sunday
}

// 是否是工作日
func (this Datebin) IsWeekday() bool {
    if this.IsInvalid() {
        return false
    }

    return !this.IsSaturday() && !this.IsSunday()
}

// 是否是周末
func (this Datebin) IsWeekend() bool {
    if this.IsInvalid() {
        return false
    }

    return this.IsSaturday() || this.IsSunday()
}

// 是否是昨天
func (this Datebin) IsYesterday() bool {
    if this.IsInvalid() {
        return false
    }

    return this.DateString() == this.Now().Offset("day", -1).DateString()
}

// 是否是今天
func (this Datebin) IsToday() bool {
    if this.IsInvalid() {
        return false
    }

    return this.DateString() == this.Now().DateString()
}

// 是否是明天
func (this Datebin) IsTomorrow() bool {
    if this.IsInvalid() {
        return false
    }

    return this.DateString() == this.Now().Offset("day", +1).DateString()
}
