package datebin

import (
	"strconv"
	"strings"
	"time"
)

/**
 * 时间间隔 / diff time
 *
 * @create 2022-3-9
 * @author deatil
 */
type DiffTime struct {
	// 开始时间 / start time
	Start Datebin

	// 结束时间 / end time
	End Datebin
}

// 构造函数
// new DiffTime
func NewDiffTime(start Datebin, end Datebin) DiffTime {
	return DiffTime{
		Start: start,
		End:   end,
	}
}

// 设置开始时间
// set start time
func (this DiffTime) SetStart(start Datebin) DiffTime {
	this.Start = start

	return this
}

// 设置结束时间
// set end time
func (this DiffTime) SetEnd(end Datebin) DiffTime {
	this.End = end

	return this
}

// 获取开始时间
// get start time
func (this DiffTime) GetStart() Datebin {
	return this.Start
}

// 获取结束时间
// get end time
func (this DiffTime) GetEnd() Datebin {
	return this.End
}

// 获取相差秒
// get diff Seconds
func (this DiffTime) Seconds() int64 {
	return this.End.Timestamp() - this.Start.Timestamp()
}

// 获取相差秒，绝对值
// get diff abs Seconds
func (this DiffTime) SecondsAbs() int64 {
	return absFormat(this.Seconds())
}

// 获取相差分钟
// get diff Minutes
func (this DiffTime) Minutes() int64 {
	return this.Seconds() / SecondsPerMinute
}

// 获取相差分钟，绝对值
// get diff abs Minutes
func (this DiffTime) MinutesAbs() int64 {
	return absFormat(this.Minutes())
}

// 获取相差小时
// get diff Hours
func (this DiffTime) Hours() int64 {
	return this.Seconds() / SecondsPerHour
}

// 获取相差小时，绝对值
// get diff abs Hours
func (this DiffTime) HoursAbs() int64 {
	return absFormat(this.Hours())
}

// 获取相差天
// get diff Days
func (this DiffTime) Days() int64 {
	return this.Seconds() / SecondsPerDay
}

// 获取相差天，绝对值
// get diff abs Days
func (this DiffTime) DaysAbs() int64 {
	return absFormat(this.Days())
}

// 获取相差周
// get diff Weeks
func (this DiffTime) Weeks() int64 {
	return this.Days() / DaysPerWeek
}

// 获取相差周，绝对值
// get diff abs Weeks
func (this DiffTime) WeeksAbs() int64 {
	return absFormat(this.Weeks())
}

// 获取相差月份
// get diff Months
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
		if int(this.HoursAbs()) < this.Start.DaysInMonth()*HoursPerDay {
			return int64(0)
		}

		return int64(dm)
	}

	return int64(dy*MonthsPerYear + dm)
}

// 获取相差月份，绝对值
// get diff abs Months
func (this DiffTime) MonthsAbs() int64 {
	return absFormat(this.Months())
}

// 获取相差年
// get diff Years
func (this DiffTime) Years() int64 {
	return this.Months() / MonthsPerYear
}

// 获取相差年，绝对值
// get diff abs Years
func (this DiffTime) YearsAbs() int64 {
	return absFormat(this.Years())
}

// 计算两个日期之间的持续时间
// get Duration data
func (this DiffTime) DurationBetween() time.Duration {
	return this.End.time.Sub(this.Start.time)
}

// 返回持续时间为人类可读的数据
// return Duration datas
func (this DiffTime) DurationBetweens() (days, hours, minutes, seconds int) {
	duration := this.DurationBetween()

	days = int(duration.Hours() / 24)
	hours = int(duration.Hours()) % 24
	minutes = int(duration.Minutes()) % 60
	seconds = int(duration.Seconds()) % 60

	return
}

// 计算两个日期之间的持续时间，绝对值
// get abs Duration data
func (this DiffTime) DurationBetweenAbs() time.Duration {
	return this.End.time.Sub(this.Start.time).Abs()
}

// 返回持续时间为人类可读的数据，绝对值
// return abs Duration datas
func (this DiffTime) DurationBetweensAbs() (days, hours, minutes, seconds int) {
	duration := this.DurationBetweenAbs()

	days = int(duration.Hours() / 24)
	hours = int(duration.Hours()) % 24
	minutes = int(duration.Minutes()) % 60
	seconds = int(duration.Seconds()) % 60

	return
}

// 获取格式化
// get diff Formatter
func (this DiffTime) Formatter() Formatter {
	return NewFormatter().FromSecond(this.Seconds())
}

// 格式化输出
// output format data
func (this DiffTime) Format(str string) string {
	// 格式化
	formatter := NewFormatter().FromSecond(this.Seconds())

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

		"{WW}": int64(weeks),
		"{DD}": int64(days),
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
