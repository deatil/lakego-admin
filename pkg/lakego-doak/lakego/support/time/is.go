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

// 是否是 Utc 时区
func (this Datebin) IsUtc() bool {
    return this.GetTimezone() == LocationUTC
}

// 是否是本地时区
func (this Datebin) IsLocal() bool {
    return this.GetTimezone() == this.Now().GetTimezone()
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

// 是否是春季
func (this Datebin) IsSpring() bool {
    if this.IsInvalid() {
        return false
    }

    if this.Month() == 3 || this.Month() == 4 || this.Month() == 5 {
        return true
    }

    return false
}

// 是否是夏季
func (this Datebin) IsSummer() bool {
    if this.IsInvalid() {
        return false
    }

    if this.Month() == 6 || this.Month() == 7 || this.Month() == 8 {
        return true
    }

    return false
}

// 是否是秋季
func (this Datebin) IsAutumn() bool {
    if this.IsInvalid() {
        return false
    }

    if this.Month() == 9 || this.Month() == 10 || this.Month() == 11 {
        return true
    }

    return false
}

// 是否是冬季
func (this Datebin) IsWinter() bool {
    if this.IsInvalid() {
        return false
    }

    if this.Month() == 12 || this.Month() == 1 || this.Month() == 2 {
        return true
    }

    return false
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

    return this.ToDateString() == this.Now().Offset("day", -1).ToDateString()
}

// 是否是今天
func (this Datebin) IsToday() bool {
    if this.IsInvalid() {
        return false
    }

    return this.ToDateString() == this.Now().ToDateString()
}

// 是否是明天
func (this Datebin) IsTomorrow() bool {
    if this.IsInvalid() {
        return false
    }

    return this.ToDateString() == this.Now().Offset("day", +1).ToDateString()
}

// 通过格式比对是否相等
func (this Datebin) IsSameAs(format string, date Datebin) bool {
    if this.IsInvalid() {
        return false
    }

    return this.Format(format) == date.Format(format)
}

// 通过格式比对是否相等
func (this Datebin) IsSameUnit(unit string, date Datebin) bool {
    if this.IsInvalid() {
        return false
    }

    units := map[string]string{
        // @call isSameUnit
        "year": "Y",
        // @call isSameUnit
        "week": "o-W",
        // @call isSameUnit
        "day": "Y-m-d",
        // @call isSameUnit
        "hour": "Y-m-d H",
        // @call isSameUnit
        "minute": "Y-m-d H:i",
        // @call isSameUnit
        "second": "Y-m-d H:i:s",
        // @call isSameUnit
        "micro": "Y-m-d H:i:s.u",
        // @call isSameUnit
        "microsecond": "Y-m-d H:i:s.u",
    }

    _, ok := units[unit]
    if !ok {
        return false
    }

    return this.IsSameAs(units[unit], date)
}

// 是否是同一年的同一个月
func (this Datebin) IsSameYearMonth(date Datebin) bool {
    return this.IsSameAs("Y-m", date)
}

// 是否是同一个月
func (this Datebin) IsSameMonth(date Datebin) bool {
    return this.IsSameAs("m", date)
}

// 是否是一个生日
func (this Datebin) IsBirthday(date Datebin) bool {
    return this.IsSameAs("md", date)
}

// 是否是当前月最后一天
func (this Datebin) IsLastOfMonth() bool {
    return this.DayOfMonth() == this.DaysInMonth()
}

// 是否当天开始
func (this Datebin) IsStartOfDay() bool {
    return this.Format("H:i:s") == "00:00:00"
}

// 是否当天开始
func (this Datebin) IsStartOfDayWithMicrosecond() bool {
    return this.Format("H:i:s.u") == "00:00:00.000000"
}

// 是否当天结束
func (this Datebin) IsEndOfDay() bool {
    return this.Format("H:i:s") == "23:59:59"
}

// 是否当天结束
func (this Datebin) IsEndOfDayWithMicrosecond() bool {
    return this.Format("H:i:s.u") == "23:59:59.999999"
}

// 是否是半夜
func (this Datebin) IsMidnight() bool {
    return this.IsStartOfDay()
}

// 是否是中午
func (this Datebin) IsMidday(midDay ...string) bool {
    midDayAt := "12"
    if len(midDay) > 0 {
        midDayAt = midDay[0]
    }

    return this.Format("H:i:s.u") == midDayAt + ":00:00"
}
