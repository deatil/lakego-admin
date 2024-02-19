package datebin

import (
	"strings"
	"time"
)

// 间隔添加或者减少
// add or sub time
func (this Datebin) Offset(field string, offset int, timezone ...string) Datebin {
	if len(timezone) > 0 {
		this = this.SetTimezone(timezone[0])
	}

	// 设置时区
	this.time = this.time.In(this.loc)

	field = strings.ToLower(field)

	switch field {
	// 百年 / century
	case "century":
		offset = offset * YearsPerCentury
		this.time = this.time.AddDate(offset, 0, 0)
	// 十年 / decade
	case "decade":
		offset = offset * YearsPerDecade
		this.time = this.time.AddDate(offset, 0, 0)
	// 一年 / year
	case "year":
		this.time = this.time.AddDate(offset, 0, 0)
	// 季度 / quarter
	case "quarter":
		offset = offset * MonthsPerQuarter
		this.time = this.time.AddDate(0, offset, 0)
	// 一个月 / one month
	case "month":
		this.time = this.time.AddDate(0, offset, 0)
	// 一周 / one weekday
	case "weekday":
		offset = offset * DaysPerWeek
		this.time = this.time.AddDate(0, 0, offset)
	// 一天 / one day
	case "day":
		this.time = this.time.AddDate(0, 0, offset)
	// 一小时 / one hour
	case "hour":
		this.time = this.time.Add(time.Hour * time.Duration(offset))
	// 一分钟 / one minute
	case "minute":
		this.time = this.time.Add(time.Minute * time.Duration(offset))
	// 一秒 / one second
	case "second":
		this.time = this.time.Add(time.Second * time.Duration(offset))
	// 毫秒 / one millisecond
	case "millisecond", "milli":
		this.time = this.time.Add(time.Millisecond * time.Duration(offset))
	// 微妙 / one microsecond
	case "microsecond", "micro":
		this.time = this.time.Add(time.Microsecond * time.Duration(offset))
	// 纳秒 / one nanosecond
	case "nanosecond", "nano":
		this.time = this.time.Add(time.Nanosecond * time.Duration(offset))
	// 默认不处理 / default
	default:
	}

	return this
}

// 不溢出增加/减少 n 年
// add or sub year NoOverflow
func (this Datebin) OffsetYearsNoOverflow(years int) Datebin {
	// N年后本月的最后一天
	// lastday of the Month from n years after time
	last := time.Date(this.Year()+years, time.Month(this.Month()), 1, this.Hour(), this.Minute(), this.Second(), this.Nanosecond(), this.loc).AddDate(0, 1, -1)

	day := this.Day()
	if this.Day() > last.Day() {
		day = last.Day()
	}

	this.time = time.Date(last.Year(), last.Month(), day, this.Hour(), this.Minute(), this.Second(), this.Nanosecond(), this.loc)
	return this
}

// 不溢出增加/减少 n 月
// add or sub Month NoOverflow
func (this Datebin) OffsetMonthsNoOverflow(months int) Datebin {
	month := this.Month() + months

	// n+1月第一天减一天
	// the month last day
	last := time.Date(this.Year(), time.Month(month), 1, this.Hour(), this.Minute(), this.Second(), this.Nanosecond(), this.loc).AddDate(0, 1, -1)

	day := this.Day()
	if this.Day() > last.Day() {
		day = last.Day()
	}

	this.time = time.Date(last.Year(), last.Month(), day, this.Hour(), this.Minute(), this.Second(), this.Nanosecond(), this.loc)
	return this
}

// 按照持续时长字符串增加时间
// add Duration time
func (this Datebin) AddDuration(duration string) Datebin {
	td, err := time.ParseDuration(duration)
	if err != nil {
		return this.AppendError(err)
	}

	this.time = this.time.In(this.loc).Add(td)

	return this
}

// 按照持续时长字符串减少时间
// sub Duration time
func (this Datebin) SubDuration(duration string) Datebin {
	return this.AddDuration("-" + duration)
}

// 将工作日添加到日期
// add Business Days
func (this Datebin) AddBusinessDays(days int) Datebin {
	currentDate := this

	for i := 0; i < days; {
		currentDate = currentDate.AddDay()
		if currentDate.IsWeekday() {
			i++
		}
	}

	return currentDate
}
