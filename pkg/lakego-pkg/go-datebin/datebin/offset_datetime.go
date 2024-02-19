package datebin

// 前 n 百年
// sub n Centuries
func (this Datebin) SubCenturies(n uint) Datebin {
	return this.Offset("century", int(-n))
}

// 前 n 百年
// sub n Centuries noOverflow
func (this Datebin) SubCenturiesNoOverflow(n uint) Datebin {
	return this.OffsetYearsNoOverflow(int(-n) * YearsPerCentury)
}

// 前一百年
// sub one Century
func (this Datebin) SubCentury() Datebin {
	return this.SubCenturies(1)
}

// 前一百年
// sub one noOverflow
func (this Datebin) SubCenturyNoOverflow() Datebin {
	return this.SubCenturiesNoOverflow(1)
}

// 后 n 百年
// add n Centuries
func (this Datebin) AddCenturies(n uint) Datebin {
	return this.Offset("century", int(n))
}

// 后 n 百年
// add n Centuries noOverflow
func (this Datebin) AddCenturiesNoOverflow(n uint) Datebin {
	return this.OffsetYearsNoOverflow(int(n) * YearsPerCentury)
}

// 后一百年
// add one Century
func (this Datebin) AddCentury() Datebin {
	return this.AddCenturies(1)
}

// 后一百年
// add one Century noOverflow
func (this Datebin) AddCenturyNoOverflow() Datebin {
	return this.AddCenturiesNoOverflow(1)
}

// 前 n 十年
// Sub n Decades
func (this Datebin) SubDecades(n uint) Datebin {
	return this.Offset("decade", int(-n))
}

// 前 n 十年
// Sub n Decades noOverflow
func (this Datebin) SubDecadesNoOverflow(n uint) Datebin {
	return this.OffsetYearsNoOverflow(int(-n) * YearsPerDecade)
}

// 前十年
// Sub one Decade
func (this Datebin) SubDecade() Datebin {
	return this.SubDecades(1)
}

// 前十年
// Sub one Decade noOverflow
func (this Datebin) SubDecadeNoOverflow() Datebin {
	return this.SubDecadesNoOverflow(1)
}

// 后 n 十年
// Add n Decades
func (this Datebin) AddDecades(n uint) Datebin {
	return this.Offset("decade", int(n))
}

// 后 n 十年
// Add n Decades noOverflow
func (this Datebin) AddDecadesNoOverflow(n uint) Datebin {
	return this.OffsetYearsNoOverflow(int(n) * YearsPerDecade)
}

// 后十年
// add one Decade
func (this Datebin) AddDecade() Datebin {
	return this.AddDecades(1)
}

// 后十年
// add one Decade noOverflow
func (this Datebin) AddDecadeNoOverflow() Datebin {
	return this.AddDecadesNoOverflow(1)
}

// 前 n 年
// Sub n Years
func (this Datebin) SubYears(n uint) Datebin {
	return this.Offset("year", int(-n))
}

// 前 n 年
// Sub n Years NoOverflow
func (this Datebin) SubYearsNoOverflow(n uint) Datebin {
	return this.OffsetYearsNoOverflow(int(-n))
}

// 前一年
// Sub one Year
func (this Datebin) SubYear() Datebin {
	return this.SubYears(1)
}

// 前一年
// Sub one Year NoOverflow
func (this Datebin) SubYearNoOverflow() Datebin {
	return this.SubYearsNoOverflow(1)
}

// 后 n 年
// Add n Years
func (this Datebin) AddYears(n uint) Datebin {
	return this.Offset("year", int(n))
}

// 后 n 年 (月份不溢出)
// Add n Years NoOverflow
func (this Datebin) AddYearsNoOverflow(years uint) Datebin {
	return this.OffsetYearsNoOverflow(int(years))
}

// 后一年
// Add one Year
func (this Datebin) AddYear() Datebin {
	return this.AddYears(1)
}

// 后一年
// Add one Year NoOverflow
func (this Datebin) AddYearNoOverflow() Datebin {
	return this.AddYearsNoOverflow(1)
}

// 前 n 季度
// Sub n Quarters
func (this Datebin) SubQuarters(n uint) Datebin {
	return this.Offset("quarter", int(-n))
}

// 前 n 季度
// Sub n Quarters NoOverflow
func (this Datebin) SubQuartersNoOverflow(n uint) Datebin {
	return this.OffsetMonthsNoOverflow(int(-n) * MonthsPerQuarter)
}

// 前一季度
// Sub one Quarter
func (this Datebin) SubQuarter() Datebin {
	return this.SubQuarters(1)
}

// 前一季度
// Sub one Quarter NoOverflow
func (this Datebin) SubQuarterNoOverflow() Datebin {
	return this.SubQuartersNoOverflow(1)
}

// 后 n 季度
// Add n Quarters
func (this Datebin) AddQuarters(n uint) Datebin {
	return this.Offset("quarter", int(n))
}

// 后 n 季度
// Add n Quarters NoOverflow
func (this Datebin) AddQuartersNoOverflow(n uint) Datebin {
	return this.OffsetMonthsNoOverflow(int(n) * MonthsPerQuarter)
}

// 后一季度
// Add one Quarter
func (this Datebin) AddQuarter() Datebin {
	return this.AddQuarters(1)
}

// 后一季度
// Add one Quarter NoOverflow
func (this Datebin) AddQuarterNoOverflow() Datebin {
	return this.AddQuartersNoOverflow(1)
}

// 前 n 月
// Sub n Months
func (this Datebin) SubMonths(n uint) Datebin {
	return this.Offset("month", int(-n))
}

// 前 n 月
// Sub n Months NoOverflow
func (this Datebin) SubMonthsNoOverflow(n uint) Datebin {
	return this.OffsetMonthsNoOverflow(int(-n))
}

// 前一月
// Sub one Month
func (this Datebin) SubMonth() Datebin {
	return this.SubMonths(1)
}

// 前一月
// Sub one Month NoOverflow
func (this Datebin) SubMonthNoOverflow() Datebin {
	return this.SubMonthsNoOverflow(1)
}

// 后 n 月
// Add n Months
func (this Datebin) AddMonths(n uint) Datebin {
	return this.Offset("month", int(n))
}

// 后 n 月 (月份不溢出)
// Add n Months NoOverflow
func (this Datebin) AddMonthsNoOverflow(months uint) Datebin {
	return this.OffsetMonthsNoOverflow(int(months))
}

// 后一月
// Add one Month
func (this Datebin) AddMonth() Datebin {
	return this.AddMonths(1)
}

// 后一月
// Add one Month NoOverflow
func (this Datebin) AddMonthNoOverflow() Datebin {
	return this.AddMonthsNoOverflow(1)
}

// 前 n 周
// Sub n Weekdays
func (this Datebin) SubWeekdays(n uint) Datebin {
	return this.Offset("weekday", int(-n))
}

// 前一周
// Sub one Weekday
func (this Datebin) SubWeekday() Datebin {
	return this.SubWeekdays(1)
}

// 后 n 周
// Add n Weekdays
func (this Datebin) AddWeekdays(n uint) Datebin {
	return this.Offset("weekday", int(n))
}

// 后一周
// Add one Weekday
func (this Datebin) AddWeekday() Datebin {
	return this.AddWeekdays(1)
}

// 前 n 天
// Sub n Days
func (this Datebin) SubDays(n uint) Datebin {
	return this.Offset("day", int(-n))
}

// 前一天
// Sub one Day
func (this Datebin) SubDay() Datebin {
	return this.SubDays(1)
}

// 后 n 天
// Add n Days
func (this Datebin) AddDays(n uint) Datebin {
	return this.Offset("day", int(n))
}

// 后一天
// Add one Day
func (this Datebin) AddDay() Datebin {
	return this.AddDays(1)
}

// 前 n 小时
// Sub n Hours
func (this Datebin) SubHours(n uint) Datebin {
	return this.Offset("hour", int(-n))
}

// 前一小时
// Sub one Hour
func (this Datebin) SubHour() Datebin {
	return this.SubHours(1)
}

// 后 n 小时
// Add n Hours
func (this Datebin) AddHours(n uint) Datebin {
	return this.Offset("hour", int(n))
}

// 后一小时
// Add one Hour
func (this Datebin) AddHour() Datebin {
	return this.AddHours(1)
}

// 前 n 分钟
// Sub n Minutes
func (this Datebin) SubMinutes(n uint) Datebin {
	return this.Offset("minute", int(-n))
}

// 前一分钟
// Sub one Minute
func (this Datebin) SubMinute() Datebin {
	return this.SubMinutes(1)
}

// 后 n 分钟
// Add n Minutes
func (this Datebin) AddMinutes(n uint) Datebin {
	return this.Offset("minute", int(n))
}

// 后一分钟
// Add one Minute
func (this Datebin) AddMinute() Datebin {
	return this.AddMinutes(1)
}

// 前 n 秒
// Sub n Seconds
func (this Datebin) SubSeconds(n uint) Datebin {
	return this.Offset("second", int(-n))
}

// 前一秒
// Sub one Second
func (this Datebin) SubSecond() Datebin {
	return this.SubSeconds(1)
}

// 后 n 一秒
// Add n Seconds
func (this Datebin) AddSeconds(n uint) Datebin {
	return this.Offset("second", int(n))
}

// 后一秒
// Add one Second
func (this Datebin) AddSecond() Datebin {
	return this.AddSeconds(1)
}

// 前 n 毫秒
// Sub n Milliseconds
func (this Datebin) SubMilliseconds(n uint) Datebin {
	return this.Offset("millisecond", int(-n))
}

// 前一毫秒
// Sub one Millisecond
func (this Datebin) SubMillisecond() Datebin {
	return this.SubMilliseconds(1)
}

// 后 n 毫秒
// Add n Milliseconds
func (this Datebin) AddMilliseconds(n uint) Datebin {
	return this.Offset("millisecond", int(n))
}

// 后一毫秒
// Add one Millisecond
func (this Datebin) AddMillisecond() Datebin {
	return this.AddMilliseconds(1)
}

// 前 n 微妙
// Sub n Microseconds
func (this Datebin) SubMicroseconds(n uint) Datebin {
	return this.Offset("microsecond", int(-n))
}

// 前一微妙
// Sub one Microsecond
func (this Datebin) SubMicrosecond() Datebin {
	return this.SubMicroseconds(1)
}

// 后 n 微妙
// Add n Microseconds
func (this Datebin) AddMicroseconds(n uint) Datebin {
	return this.Offset("microsecond", int(n))
}

// 后一微妙
// Add one Microsecond
func (this Datebin) AddMicrosecond() Datebin {
	return this.AddMicroseconds(1)
}

// 前 n 纳秒
// Sub n Nanoseconds
func (this Datebin) SubNanoseconds(n uint) Datebin {
	return this.Offset("nanosecond", int(-n))
}

// 前一纳秒
// Sub one Nanosecond
func (this Datebin) SubNanosecond() Datebin {
	return this.SubNanoseconds(1)
}

// 后 n 纳秒
// Add n Nanoseconds
func (this Datebin) AddNanoseconds(n uint) Datebin {
	return this.Offset("nanosecond", int(n))
}

// 后一纳秒
// Add one Nanosecond
func (this Datebin) AddNanosecond() Datebin {
	return this.AddNanoseconds(1)
}
