package time

// 默认返回
func (this Datebin) String() string {
    return this.ToDatetimeString()
}

// 返回字符
func (this Datebin) ToString(timezone ...string) string {
    if len(timezone) > 0 {
        this.loc, this.Error = this.GetLocationByTimezone(timezone[0])
    }

    if this.IsInvalid() {
        return ""
    }

    return this.time.In(this.loc).String()
}

// 获取当前季节(以气象划分)
func (this Datebin) ToSeasonString() string {
    if this.IsInvalid() {
        return ""
    }

    name := ""
    switch {
        // 春季
        case this.Month() == 3 || this.Month() == 4 || this.Month() == 5:
            name = "Spring"
        // 夏季
        case this.Month() == 6 || this.Month() == 7 || this.Month() == 8:
            name = "Summer"
        // 秋季
        case this.Month() == 9 || this.Month() == 10 || this.Month() == 11:
            name = "Autumn"
        // 冬季
        case this.Month() == 12 || this.Month() == 1 || this.Month() == 2:
            name = "Winter"
    }

    return name
}

// 周几
func (this Datebin) ToWeekdayString() string {
    weekday := this.Weekday()

    return Weeks[weekday]
}

// 日期时间
func (this Datebin) ToDatetimeString() string {
    return this.Format(DatetimeFormat)
}

// 日期
func (this Datebin) ToDateString() string {
    return this.Format(DateFormat)
}

// 时间
func (this Datebin) ToTimeString() string {
    return this.Format(TimeFormat)
}
