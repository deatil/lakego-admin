package datebin

// 通过格式字符比对是否相等
// if a and b Is Same with format string ?
func (this Datebin) IsSameAs(format string, date Datebin) bool {
	if this.IsInvalid() {
		return false
	}

	return this.Format(format) == date.Format(format)
}

// 通过布局字符比对是否相等
// if a and b Is Same With Layout string ?
func (this Datebin) IsSameAsWithLayout(layout string, date Datebin) bool {
	if this.IsInvalid() {
		return false
	}

	return this.Layout(layout) == date.Layout(layout)
}

// 通过预设格式字符比对是否相等
// unit 预设有: year | week | day | hour | minute | second | micro | microsecond
// if a and b Is Same with Unit ?
// unit has: year | week | day | hour | minute | second | micro | microsecond
func (this Datebin) IsSameUnit(unit string, date Datebin) bool {
	if this.IsInvalid() {
		return false
	}

	// 默认比对列表
	units := map[string]string{
		"year":        "Y",
		"week":        "o-W",
		"day":         "Y-m-d",
		"hour":        "Y-m-d H",
		"minute":      "Y-m-d H:i",
		"second":      "Y-m-d H:i:s",
		"micro":       "Y-m-d H:i:s.u",
		"microsecond": "Y-m-d H:i:s.u",
	}

	_, ok := units[unit]
	if !ok {
		return false
	}

	return this.IsSameAs(units[unit], date)
}

// 是否同一年
// if a and b Is Same Year ?
func (this Datebin) IsSameYear(date Datebin) bool {
	if this.IsInvalid() {
		return false
	}

	return this.Year() == date.Year()
}

// 是否是同一个月
// if a and b Is Same Month ?
func (this Datebin) IsSameMonth(date Datebin) bool {
	if this.IsInvalid() {
		return false
	}

	return this.Month() == date.Month()
}

// 是否同一天
// if a and b Is Same Day ?
func (this Datebin) IsSameDay(date Datebin) bool {
	if this.IsInvalid() {
		return false
	}

	return this.Day() == date.Day()
}

// 是否同一小时
// if a and b Is Same Hour ?
func (this Datebin) IsSameHour(date Datebin) bool {
	if this.IsInvalid() {
		return false
	}

	return this.Hour() == date.Hour()
}

// 是否同一分钟
// if a and b Is Same Minute ?
func (this Datebin) IsSameMinute(date Datebin) bool {
	if this.IsInvalid() {
		return false
	}

	return this.Minute() == date.Minute()
}

// 是否同一秒
// if a and b Is Same Second ?
func (this Datebin) IsSameSecond(date Datebin) bool {
	if this.IsInvalid() {
		return false
	}

	return this.Second() == date.Second()
}

// 是否是同一年的同一个月
// if a and b Is Same Year and Month ?
func (this Datebin) IsSameYearMonth(date Datebin) bool {
	if this.IsInvalid() {
		return false
	}

	return this.IsSameYear(date) && this.IsSameMonth(date)
}

// 是否是同一个月的同一天
// if a and b Is Same Month and Day ?
func (this Datebin) IsSameMonthDay(date Datebin) bool {
	if this.IsInvalid() {
		return false
	}

	return this.IsSameMonth(date) && this.IsSameDay(date)
}

// 是否是同一年的同一个月的同一天
// if a and b Is Same Year, Month and Day ?
func (this Datebin) IsSameYearMonthDay(date Datebin) bool {
	if this.IsInvalid() {
		return false
	}

	return this.IsSameYear(date) && this.IsSameMonth(date) && this.IsSameDay(date)
}

// 是否是相同生日日期
// if a and b Is Same Birthday ?
func (this Datebin) IsSameBirthday(date Datebin) bool {
	return this.IsSameMonthDay(date)
}
