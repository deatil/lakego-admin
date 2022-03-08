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
