package time

import (
    "strconv"
    "strings"
)

/**
 * 时间判断
 *
 * @create 2022-3-9
 * @author deatil
 */
type Difftime struct {
    // 开始时间
    Start Datebin

    // 结束时间
    End Datebin
}

// 设置开始时间
func (this Difftime) SetStart(start Datebin) Difftime {
    this.Start = start

    return this
}

// 设置结束时间
func (this Difftime) SetEnd(end Datebin) Difftime {
    this.End = end

    return this
}

// 开始时间
func (this Difftime) GetStart() Datebin {
    return this.Start
}

// 结束时间
func (this Difftime) GetEnd() Datebin {
    return this.End
}

// 相差秒
func (this Difftime) Seconds() int64 {
    return this.End.Timestamp() - this.Start.Timestamp()
}

// 相差秒
func (this Difftime) SecondsAbs() int64 {
    return this.AbsFormat(this.Seconds())
}

// 相差分钟
func (this Difftime) Minutes() int64 {
    return this.Seconds() / SecondsPerMinute
}

// 相差分钟
func (this Difftime) MinutesAbs() int64 {
    return this.AbsFormat(this.Minutes())
}

// 相差小时
func (this Difftime) Hours() int64 {
    return this.Seconds() / SecondsPerHour
}

// 相差小时
func (this Difftime) HoursAbs() int64 {
    return this.AbsFormat(this.Hours())
}

// 相差天
func (this Difftime) Days() int64 {
    return this.Seconds() / SecondsPerDay
}

// 相差天
func (this Difftime) DaysAbs() int64 {
    return this.AbsFormat(this.Days())
}

// 相差天
func (this Difftime) Weeks() int64 {
    return this.Days() / DaysPerWeek
}

// 相差天
func (this Difftime) WeeksAbs() int64 {
    return this.AbsFormat(this.Weeks())
}

// 月份
func (this Difftime) Months() int64 {
    dy := this.End.Year() - this.Start.Year()
    dm := this.End.Month() - this.Start.Month()
    dd := this.End.Day() - this.Start.Day()

    if dd < 0 {
        dm = dm - 1
    }

    if dy == 0 && dm == 0 {
        return int64(0)
    }

    if dy == 0 && dm != 0 && dd != 0 {
        if int(this.HoursAbs()) < this.Start.DaysInMonth() * HoursPerDay {
            return int64(0)
        }

        return int64(dm)
    }

    return int64(dy * MonthsPerYear + dm)
}

// 相差月份
func (this Difftime) MonthsAbs() int64 {
    return this.AbsFormat(this.Months())
}

// 相差年
func (this Difftime) Years() int64 {
    return this.Months() / MonthsPerYear
}

// 相差年
func (this Difftime) YearsAbs() int64 {
    return this.AbsFormat(this.Years())
}

// 格式化输出
func (this Difftime) Format(str string) string {
    formatMap := map[string]int64{
        "{Y}": this.Years(),
        "{m}": this.Months(),
        "{d}": this.Days(),
        "{H}": this.Hours(),
        "{i}": this.Minutes(),
        "{s}": this.Seconds(),
        "{w}": this.Weeks(),
    }

    for format, data := range formatMap {
        str = strings.Replace(str, format, strconv.FormatInt(data, 10), -1)
    }

    return str
}

// 绝对值格式化
func (this Difftime) AbsFormat(value int64) int64 {
    return (value ^ value>>31) - value>>31
}

// 构造函数
func NewDifftime(start Datebin, end Datebin) Difftime {
    return Difftime{
        Start: start,
        End: end,
    }
}
