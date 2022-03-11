package datebin

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

    // 默认比对列表
    units := map[string]string{
        "year": "Y",
        "week": "o-W",
        "day": "Y-m-d",
        "hour": "Y-m-d H",
        "minute": "Y-m-d H:i",
        "second": "Y-m-d H:i:s",
        "micro": "Y-m-d H:i:s.u",
        "microsecond": "Y-m-d H:i:s.u",
    }

    _, ok := units[unit]
    if !ok {
        return false
    }

    return this.IsSameAs(units[unit], date)
}

// 是否同一年
func (this Datebin) IsSameYear(date Datebin) bool {
    return this.Year() == date.Year()
}

// 是否是同一个月
func (this Datebin) IsSameMonth(date Datebin) bool {
    return this.Month() == date.Month()
}

// 是否同一天
func (this Datebin) IsSameDay(date Datebin) bool {
    return this.Day() == date.Day()
}

// 是否同一小时
func (this Datebin) IsSameHour(date Datebin) bool {
    return this.Hour() == date.Hour()
}

// 是否同一分钟
func (this Datebin) IsSameMinute(date Datebin) bool {
    return this.Minute() == date.Minute()
}

// 是否同一秒
func (this Datebin) IsSameSecond(date Datebin) bool {
    return this.Second() == date.Second()
}

// 是否是同一年的同一个月
func (this Datebin) IsSameYearMonth(date Datebin) bool {
    return this.IsSameYear(date) && this.IsSameMonth(date)
}

// 是否是同一个月的同一天
func (this Datebin) IsSameMonthDay(date Datebin) bool {
    return this.IsSameMonth(date) && this.IsSameDay(date)
}

// 是否是同一年的同一个月的同一天
func (this Datebin) IsSameYearMonthDay(date Datebin) bool {
    return this.IsSameYear(date) && this.IsSameMonth(date) && this.IsSameDay(date)
}

// 是否是一个生日
func (this Datebin) IsBirthday(date Datebin) bool {
    return this.IsSameAs("md", date)
}
