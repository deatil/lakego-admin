package datebin

// 获取本月的总天数
func (this Datebin) DaysInMonth() int {
    if this.IsInvalid() {
        return 0
    }

    return this.MonthEnd().time.In(this.loc).Day()
}

// 获取本年的第几月
func (this Datebin) MonthOfYear() int {
    if this.IsInvalid() {
        return 0
    }

    return int(this.time.In(this.loc).Month())
}

// 获取本年的第几天
func (this Datebin) DayOfYear() int {
    if this.IsInvalid() {
        return 0
    }

    return this.time.In(this.loc).YearDay()
}

// 获取本月的第几天
func (this Datebin) DayOfMonth() int {
    if this.IsInvalid() {
        return 0
    }

    return this.time.In(this.loc).Day()
}

// 获取本周的第几天
func (this Datebin) DayOfWeek() int {
    if this.IsInvalid() {
        return 0
    }

    day := int(this.time.In(this.loc).Weekday())
    if day == 0 {
        return DaysPerWeek
    }

    return day
}

// 获取本年的第几周
func (this Datebin) WeekOfYear() int {
    if this.IsInvalid() {
        return 0
    }

    _, week := this.time.In(this.loc).ISOWeek()
    return week
}
