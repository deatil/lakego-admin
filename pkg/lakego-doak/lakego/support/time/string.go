package time

var (
    // 周列表
    Weeks = []string{
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
    }

    // 格式化字符
    FormatDatetimeStr = "2006-01-02 15:04:05"
    FormatDateStr = "2006-01-02"
    FormatTimeStr = "15:04:05"
)

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

// 默认返回
func (this Datebin) String() string {
    return this.TimeString()
}

// 日期时间
func (this Datebin) DatetimeString() string {
    return this.Format(FormatDatetimeStr)
}

// 日期
func (this Datebin) DateString() string {
    return this.Format(FormatDateStr)
}

// 时间
func (this Datebin) TimeString() string {
    return this.Format(FormatTimeStr)
}

// 周
func (this Datebin) WeekdayString() string {
    weekday := this.Weekday()

    return Weeks[weekday]
}
