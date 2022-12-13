package datebin

import (
    "strconv"
    "strings"
)

// 构造函数
func NewDiffTime(start Datebin, end Datebin) DiffTime {
    return DiffTime{
        Start: start,
        End: end,
    }
}

/**
 * 时间判断
 *
 * @create 2022-3-9
 * @author deatil
 */
type DiffTime struct {
    // 开始时间
    Start Datebin

    // 结束时间
    End Datebin
}

// 设置开始时间
func (this DiffTime) SetStart(start Datebin) DiffTime {
    this.Start = start

    return this
}

// 设置结束时间
func (this DiffTime) SetEnd(end Datebin) DiffTime {
    this.End = end

    return this
}

// 开始时间
func (this DiffTime) GetStart() Datebin {
    return this.Start
}

// 结束时间
func (this DiffTime) GetEnd() Datebin {
    return this.End
}

// 相差秒
func (this DiffTime) Seconds() int64 {
    return this.End.Timestamp() - this.Start.Timestamp()
}

// 相差秒，绝对值
func (this DiffTime) SecondsAbs() int64 {
    return this.AbsFormat(this.Seconds())
}

// 相差分钟
func (this DiffTime) Minutes() int64 {
    return this.Seconds() / SecondsPerMinute
}

// 相差分钟，绝对值
func (this DiffTime) MinutesAbs() int64 {
    return this.AbsFormat(this.Minutes())
}

// 相差小时
func (this DiffTime) Hours() int64 {
    return this.Seconds() / SecondsPerHour
}

// 相差小时，绝对值
func (this DiffTime) HoursAbs() int64 {
    return this.AbsFormat(this.Hours())
}

// 相差天
func (this DiffTime) Days() int64 {
    return this.Seconds() / SecondsPerDay
}

// 相差天，绝对值
func (this DiffTime) DaysAbs() int64 {
    return this.AbsFormat(this.Days())
}

// 相差周
func (this DiffTime) Weeks() int64 {
    return this.Days() / DaysPerWeek
}

// 相差周，绝对值
func (this DiffTime) WeeksAbs() int64 {
    return this.AbsFormat(this.Weeks())
}

// 相差月份
func (this DiffTime) Months() int64 {
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

// 相差月份，绝对值
func (this DiffTime) MonthsAbs() int64 {
    return this.AbsFormat(this.Months())
}

// 相差年
func (this DiffTime) Years() int64 {
    return this.Months() / MonthsPerYear
}

// 相差年，绝对值
func (this DiffTime) YearsAbs() int64 {
    return this.AbsFormat(this.Years())
}

// 格式化输出
func (this DiffTime) Format(str string) string {
    // 格式化
    formatter := NewFormatter().FromSecond(this.SecondsAbs())

    // 使用周数和天数
    weeks, days := formatter.WeekAndDay()

    formatMap := map[string]int64{
        "{Y}": this.Years(),
        "{m}": this.Months(),
        "{d}": this.Days(),
        "{H}": this.Hours(),
        "{i}": this.Minutes(),
        "{s}": this.Seconds(),
        "{w}": this.Weeks(),

        "{www}": int64(weeks),
        "{ddd}": int64(days),
        "{dd}": int64(formatter.Day()),
        "{HH}": int64(formatter.Hour()),
        "{ii}": int64(formatter.Minute()),
        "{ss}": int64(formatter.Second()),
    }

    for format, data := range formatMap {
        str = strings.Replace(str, format, strconv.FormatInt(data, 10), -1)
    }

    return str
}

// 取绝对值
func (this DiffTime) AbsFormat(value int64) int64 {
    return this.Start.AbsFormat(value)
}
