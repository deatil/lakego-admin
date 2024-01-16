package datebin

// 前 n 百年
// sub n Centuries
func (this Datebin) SubCenturies(century uint) Datebin {
	return this.Offset("century", int(-century))
}

// 前 n 百年
// sub n Centuries noOverflow
func (this Datebin) SubCenturiesNoOverflow(century uint) Datebin {
	return this.OffsetYearsNoOverflow(int(-century) * YearsPerCentury)
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
func (this Datebin) AddCenturies(century uint) Datebin {
	return this.Offset("century", int(century))
}

// 后 n 百年
// add n Centuries noOverflow
func (this Datebin) AddCenturiesNoOverflow(century uint) Datebin {
	return this.OffsetYearsNoOverflow(int(century) * YearsPerCentury)
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
func (this Datebin) SubDecades(data uint) Datebin {
	return this.Offset("decade", int(-data))
}

// 前 n 十年
func (this Datebin) SubDecadesNoOverflow(data uint) Datebin {
	return this.OffsetYearsNoOverflow(int(-data) * YearsPerDecade)
}

// 前十年
func (this Datebin) SubDecade() Datebin {
	return this.SubDecades(1)
}

// 前十年
func (this Datebin) SubDecadeNoOverflow() Datebin {
	return this.SubDecadesNoOverflow(1)
}

// 后 n 十年
func (this Datebin) AddDecades(data uint) Datebin {
	return this.Offset("decade", int(data))
}

// 后 n 十年
func (this Datebin) AddDecadesNoOverflow(data uint) Datebin {
	return this.OffsetYearsNoOverflow(int(data) * YearsPerDecade)
}

// 后十年
func (this Datebin) AddDecade() Datebin {
	return this.AddDecades(1)
}

// 后十年
func (this Datebin) AddDecadeNoOverflow() Datebin {
	return this.AddDecadesNoOverflow(1)
}

// 前 n 年
func (this Datebin) SubYears(data uint) Datebin {
	return this.Offset("year", int(-data))
}

// 前 n 年
func (this Datebin) SubYearsNoOverflow(data uint) Datebin {
	return this.OffsetYearsNoOverflow(int(-data))
}

// 前一年
func (this Datebin) SubYear() Datebin {
	return this.SubYears(1)
}

// 前一年
func (this Datebin) SubYearNoOverflow() Datebin {
	return this.SubYearsNoOverflow(1)
}

// 后 n 年
func (this Datebin) AddYears(data uint) Datebin {
	return this.Offset("year", int(data))
}

// 后 n 年 (月份不溢出)
func (this Datebin) AddYearsNoOverflow(years uint) Datebin {
	return this.OffsetYearsNoOverflow(int(years))
}

// 后一年
func (this Datebin) AddYear() Datebin {
	return this.AddYears(1)
}

// 后一年
func (this Datebin) AddYearNoOverflow() Datebin {
	return this.AddYearsNoOverflow(1)
}

// 前 n 季度
func (this Datebin) SubQuarters(data uint) Datebin {
	return this.Offset("quarter", int(-data))
}

// 前 n 季度
func (this Datebin) SubQuartersNoOverflow(data uint) Datebin {
	return this.OffsetMonthsNoOverflow(int(-data) * MonthsPerQuarter)
}

// 前一季度
func (this Datebin) SubQuarter() Datebin {
	return this.SubQuarters(1)
}

// 前一季度
func (this Datebin) SubQuarterNoOverflow() Datebin {
	return this.SubQuartersNoOverflow(1)
}

// 后 n 季度
func (this Datebin) AddQuarters(data uint) Datebin {
	return this.Offset("quarter", int(data))
}

// 后 n 季度
func (this Datebin) AddQuartersNoOverflow(data uint) Datebin {
	return this.OffsetMonthsNoOverflow(int(data) * MonthsPerQuarter)
}

// 后一季度
func (this Datebin) AddQuarter() Datebin {
	return this.AddQuarters(1)
}

// 后一季度
func (this Datebin) AddQuarterNoOverflow() Datebin {
	return this.AddQuartersNoOverflow(1)
}

// 前 n 月
func (this Datebin) SubMonths(data uint) Datebin {
	return this.Offset("month", int(-data))
}

// 前 n 月
func (this Datebin) SubMonthsNoOverflow(data uint) Datebin {
	return this.OffsetMonthsNoOverflow(int(-data))
}

// 前一月
func (this Datebin) SubMonth() Datebin {
	return this.SubMonths(1)
}

// 前一月
func (this Datebin) SubMonthNoOverflow() Datebin {
	return this.SubMonthsNoOverflow(1)
}

// 后 n 月
func (this Datebin) AddMonths(data uint) Datebin {
	return this.Offset("month", int(data))
}

// 后 n 月 (月份不溢出)
func (this Datebin) AddMonthsNoOverflow(months uint) Datebin {
	return this.OffsetMonthsNoOverflow(int(months))
}

// 后一月
func (this Datebin) AddMonth() Datebin {
	return this.AddMonths(1)
}

// 后一月
func (this Datebin) AddMonthNoOverflow() Datebin {
	return this.AddMonthsNoOverflow(1)
}

// 前 n 周
func (this Datebin) SubWeekdays(data uint) Datebin {
	return this.Offset("weekday", int(-data))
}

// 前一周
func (this Datebin) SubWeekday() Datebin {
	return this.SubWeekdays(1)
}

// 后 n 周
func (this Datebin) AddWeekdays(data uint) Datebin {
	return this.Offset("weekday", int(data))
}

// 后一周
func (this Datebin) AddWeekday() Datebin {
	return this.AddWeekdays(1)
}

// 前 n 天
func (this Datebin) SubDays(data uint) Datebin {
	return this.Offset("day", int(-data))
}

// 前一天
func (this Datebin) SubDay() Datebin {
	return this.SubDays(1)
}

// 后 n 天
func (this Datebin) AddDays(data uint) Datebin {
	return this.Offset("day", int(data))
}

// 后一天
func (this Datebin) AddDay() Datebin {
	return this.AddDays(1)
}

// 前 n 小时
func (this Datebin) SubHours(data uint) Datebin {
	return this.Offset("hour", int(-data))
}

// 前一小时
func (this Datebin) SubHour() Datebin {
	return this.SubHours(1)
}

// 后 n 小时
func (this Datebin) AddHours(data uint) Datebin {
	return this.Offset("hour", int(data))
}

// 后一小时
func (this Datebin) AddHour() Datebin {
	return this.AddHours(1)
}

// 前 n 分钟
func (this Datebin) SubMinutes(data uint) Datebin {
	return this.Offset("minute", int(-data))
}

// 前一分钟
func (this Datebin) SubMinute() Datebin {
	return this.SubMinutes(1)
}

// 后 n 分钟
func (this Datebin) AddMinutes(data uint) Datebin {
	return this.Offset("minute", int(data))
}

// 后 n 分钟
func (this Datebin) AddMinute() Datebin {
	return this.AddMinutes(1)
}

// 前 n 秒
func (this Datebin) SubSeconds(data uint) Datebin {
	return this.Offset("second", int(-data))
}

// 前一秒
func (this Datebin) SubSecond() Datebin {
	return this.SubSeconds(1)
}

// 后 n 一秒
func (this Datebin) AddSeconds(data uint) Datebin {
	return this.Offset("second", int(data))
}

// 后一秒
func (this Datebin) AddSecond() Datebin {
	return this.AddSeconds(1)
}

// 前 n 毫秒
func (this Datebin) SubMilliseconds(data uint) Datebin {
	return this.Offset("millisecond", int(-data))
}

// 前一毫秒
func (this Datebin) SubMillisecond() Datebin {
	return this.SubMilliseconds(1)
}

// 后 n 毫秒
func (this Datebin) AddMilliseconds(data uint) Datebin {
	return this.Offset("millisecond", int(data))
}

// 后一毫秒
func (this Datebin) AddMillisecond() Datebin {
	return this.AddMilliseconds(1)
}

// 前 n 微妙
func (this Datebin) SubMicroseconds(data uint) Datebin {
	return this.Offset("microsecond", int(-data))
}

// 前一微妙
func (this Datebin) SubMicrosecond() Datebin {
	return this.SubMicroseconds(1)
}

// 后 n 微妙
func (this Datebin) AddMicroseconds(data uint) Datebin {
	return this.Offset("microsecond", int(data))
}

// 后一微妙
func (this Datebin) AddMicrosecond() Datebin {
	return this.AddMicroseconds(1)
}

// 前 n 纳秒
func (this Datebin) SubNanoseconds(data uint) Datebin {
	return this.Offset("nanosecond", int(-data))
}

// 前一纳秒
func (this Datebin) SubNanosecond() Datebin {
	return this.SubNanoseconds(1)
}

// 后 n 纳秒
func (this Datebin) AddNanoseconds(data uint) Datebin {
	return this.Offset("nanosecond", int(data))
}

// 后一纳秒
func (this Datebin) AddNanosecond() Datebin {
	return this.AddNanoseconds(1)
}
