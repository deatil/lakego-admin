package time

import (
    "time"
    "strings"
)

// 间隔
func (this Datebin) Offset(field string, offset int, timezone ...string) Datebin {
    if len(timezone) > 0 {
        this.loc, this.Error = this.GetLocationByTimezone(timezone[0])
    }

    if this.Error != nil {
        return this
    }

    this.time = this.time.In(this.loc)

    field = strings.ToLower(field)

    switch field {
        case "year":
            this.time = this.time.AddDate(offset, 0, 0)
        case "month":
            this.time = this.time.AddDate(0, offset, 0)
        case "day":
            this.time = this.time.AddDate(0, 0, offset)
        case "hour":
            this.time = this.time.Add(time.Hour * time.Duration(offset))
        case "minute":
            this.time = this.time.Add(time.Minute * time.Duration(offset))
        case "second":
            this.time = this.time.Add(time.Second * time.Duration(offset))
        default:
            this.time = this.time.Add(time.Second * time.Duration(offset))
    }

    return this
}

// 前 n 年，默认一年
func (this Datebin) SubYear(data ...uint64) Datebin {
    offset := -1

    if len(data) > 0 {
        offset = 0 - int(data[0])
    }

    return this.Offset("year", offset)
}

// 后 n 年，默认一年
func (this Datebin) AddYear(data ...uint64) Datebin {
    offset := 1

    if len(data) > 0 {
        offset = int(data[0])
    }

    return this.Offset("year", offset)
}

// 前 n 月，默认一月
func (this Datebin) SubMonth(data ...uint64) Datebin {
    offset := -1

    if len(data) > 0 {
        offset = 0 - int(data[0])
    }

    return this.Offset("month", offset)
}

// 后 n 月，默认一月
func (this Datebin) AddMonth(data ...uint64) Datebin {
    offset := 1

    if len(data) > 0 {
        offset = int(data[0])
    }

    return this.Offset("month", offset)
}

// 前 n 天，默认一天
func (this Datebin) SubDay(data ...uint64) Datebin {
    offset := -1

    if len(data) > 0 {
        offset = 0 - int(data[0])
    }

    return this.Offset("day", offset)
}

// 后 n 天，默认一天
func (this Datebin) AddDay(data ...uint64) Datebin {
    offset := 1

    if len(data) > 0 {
        offset = int(data[0])
    }

    return this.Offset("day", offset)
}

// 前 n 小时，默认一小时
func (this Datebin) SubHour(data ...uint64) Datebin {
    offset := -1

    if len(data) > 0 {
        offset = 0 - int(data[0])
    }

    return this.Offset("hour", offset)
}

// 后 n 小时，默认一小时
func (this Datebin) AddHour(data ...uint64) Datebin {
    offset := 1

    if len(data) > 0 {
        offset = int(data[0])
    }

    return this.Offset("hour", offset)
}

// 前 n 分钟，默认一分钟
func (this Datebin) SubMinute(data ...uint64) Datebin {
    offset := -1

    if len(data) > 0 {
        offset = 0 - int(data[0])
    }

    return this.Offset("minute", offset)
}

// 后 n 分钟，默认一分钟
func (this Datebin) AddMinute(data ...uint64) Datebin {
    offset := 1

    if len(data) > 0 {
        offset = int(data[0])
    }

    return this.Offset("minute", offset)
}

// 前 n 秒，默认一秒
func (this Datebin) SubSecond(data ...uint64) Datebin {
    offset := -1

    if len(data) > 0 {
        offset = 0 - int(data[0])
    }

    return this.Offset("second", offset)
}

// 后 n 秒，默认一秒
func (this Datebin) AddSecond(data ...uint64) Datebin {
    offset := 1

    if len(data) > 0 {
        offset = int(data[0])
    }

    return this.Offset("second", offset)
}
