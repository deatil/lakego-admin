package datebin

import (
    "time"
)

// 当前
func (this Datebin) Now(timezone ...string) Datebin {
    if len(timezone) > 0 {
        this.loc, this.Error = this.GetLocationByTimezone(timezone[0])
    }

    if this.Error != nil {
        return this
    }

    this.time = time.Now().In(this.loc)
    return this
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

// 返回年月日时分秒数据
func (this Datebin) Datetime() (year, month, day, hour, minute, second int) {
    if this.IsInvalid() {
        return
    }

    t := this.time.In(this.loc)

    var timeMonth time.Month

    year, timeMonth, day = t.Date()
    hour, minute, second = t.Clock()

    return year, int(timeMonth), day, hour, minute, second
}

// 返回年月日数据
func (this Datebin) Date() (year, month, day int) {
    if this.IsInvalid() {
        return
    }

    year, timeMonth, day := this.time.In(this.loc).Date()

    return year, int(timeMonth), day
}

// 返回时分秒数据
func (this Datebin) Time() (hour, minute, second int) {
    if this.IsInvalid() {
        return
    }

    return this.time.In(this.loc).Clock()
}
