package time

import (
    "time"
)

// 获取本月的总天数
func (this Datebin) DaysInMonth() int {
    if this.IsInvalid() {
        return 0
    }

    return this.MonthEnd().time.In(this.loc).Day()
}

// 获取本年的第几月
func (this Datebin) MonthInYear() int {
    if this.IsInvalid() {
        return 0
    }

    return int(this.time.In(this.loc).Month())
}

// 获取本年的第几天
func (this Datebin) DayInYear() int {
    if this.IsInvalid() {
        return 0
    }

    return this.time.In(this.loc).YearDay()
}

// 获取本月的第几天
func (this Datebin) DayInMonth() int {
    if this.IsInvalid() {
        return 0
    }

    return this.time.In(this.loc).Day()
}

// 获取本周的第几天
func (this Datebin) DayInWeek() int {
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
func (this Datebin) WeekInYear() int {
    if this.IsInvalid() {
        return 0
    }

    _, week := this.time.In(this.loc).ISOWeek()
    return week
}

// 获取当前世纪
func (this Datebin) Century() int {
    if this.IsInvalid() {
        return 0
    }

    return this.Year() / YearsPerCentury + 1
}

// 获取当前年代
func (this Datebin) Decade() int {
    if this.IsInvalid() {
        return 0
    }

    return this.Year() % YearsPerCentury / YearsPerDecade * YearsPerDecade
}

// 获取当前年
func (this Datebin) Year() int {
    if this.IsInvalid() {
        return 0
    }

    return this.time.In(this.loc).Year()
}

// 获取当前季度
func (this Datebin) Quarter() (quarter int) {
    if this.IsInvalid() {
        return 0
    }

    switch {
        case this.Month() >= 10:
            quarter = 4
        case this.Month() >= 7:
            quarter = 3
        case this.Month() >= 4:
            quarter = 2
        case this.Month() >= 1:
            quarter = 1
    }

    return
}

// 获取当前月
func (this Datebin) Month() int {
    if this.IsInvalid() {
        return 0
    }

    return this.MonthInYear()
}

// 星期几数字
func (this Datebin) Weekday() int {
    return int(this.time.In(this.loc).Weekday())
}

// 获取当前日
func (this Datebin) Day() int {
    if this.IsInvalid() {
        return 0
    }

    return this.DayInMonth()
}

// 获取当前小时
func (this Datebin) Hour() int {
    if this.IsInvalid() {
        return 0
    }

    return this.time.In(this.loc).Hour()
}

// 获取当前分钟数
func (this Datebin) Minute() int {
    if this.IsInvalid() {
        return 0
    }

    return this.time.In(this.loc).Minute()
}

// 获取当前秒数
func (this Datebin) Second() int {
    if this.IsInvalid() {
        return 0
    }

    return this.time.In(this.loc).Second()
}

// 获取当前毫秒数，3位数字
func (this Datebin) Millisecond() int {
    if this.IsInvalid() {
        return 0
    }

    return this.time.In(this.loc).Nanosecond() / 1e6
}

// 获取当前微秒数，6位数字
func (this Datebin) Microsecond() int {
    if this.IsInvalid() {
        return 0
    }

    return this.time.In(this.loc).Nanosecond() / 1e3
}

// 获取当前纳秒数，9位数字
func (this Datebin) Nanosecond() int {
    if this.IsInvalid() {
        return 0
    }

    return this.time.In(this.loc).Nanosecond()
}

// 输出秒级时间戳
func (this Datebin) Timestamp() int64 {
    if this.IsInvalid() {
        return 0
    }

    return this.time.In(this.loc).Unix()
}

// 获取毫秒级时间戳
func (this Datebin) TimestampWithMillisecond() int64 {
    if this.IsInvalid() {
        return 0
    }

    // return this.time.In(this.loc).UnixNano() / 1e6
    return this.time.In(this.loc).UnixNano() / int64(time.Millisecond)
}

// 获取微秒级时间戳
func (this Datebin) TimestampWithMicrosecond() int64 {
    if this.IsInvalid() {
        return 0
    }

    return this.time.In(this.loc).UnixNano() / int64(time.Microsecond)
}

// 获取纳秒级时间戳
func (this Datebin) TimestampWithNanosecond() int64 {
    if this.IsInvalid() {
        return 0
    }

    return this.time.In(this.loc).UnixNano()
}

// 今天
func (this Datebin) Today(timezone ...string) Datebin {
    if len(timezone) > 0 {
        this.loc, this.Error = this.GetLocationByTimezone(timezone[0])
    }

    if this.Error != nil {
        return this
    }

    var datetime Datebin
    if this.IsZero() {
        datetime = this.Now()
    } else {
        datetime = this
    }

    this.time = time.Date(datetime.Year(), time.Month(datetime.Month()), datetime.Day(), 0, 0, 0, 0, datetime.loc)

    return this
}

// 明天
func (this Datebin) Tomorrow(timezone ...string) Datebin {
    if len(timezone) > 0 {
        this.loc, this.Error = this.GetLocationByTimezone(timezone[0])
    }

    if this.Error != nil {
        return this
    }

    var datetime Datebin
    if this.IsZero() {
        datetime = this.Now().AddDay()
    } else {
        datetime = this.AddDay()
    }

    this.time = time.Date(datetime.Year(), time.Month(datetime.Month()), datetime.Day(), 0, 0, 0, 0, datetime.loc)

    return this
}

// 昨天
func (this Datebin) Yesterday(timezone ...string) Datebin {
    if len(timezone) > 0 {
        this.loc, this.Error = this.GetLocationByTimezone(timezone[0])
    }

    if this.Error != nil {
        return this
    }

    var datetime Datebin
    if this.IsZero() {
        datetime = this.Now().SubDay()
    } else {
        datetime = this.SubDay()
    }

    this.time = time.Date(datetime.Year(), time.Month(datetime.Month()), datetime.Day(), 0, 0, 0, 0, datetime.loc)

    return this
}
