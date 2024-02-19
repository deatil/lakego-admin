package datebin

// 获取当前世纪
// get Century data
func (this Datebin) Century() int {
	if this.IsInvalid() {
		return 0
	}

	return this.Year()/YearsPerCentury + 1
}

// 获取当前年代
// get Decade data
func (this Datebin) Decade() int {
	if this.IsInvalid() {
		return 0
	}

	return this.Year() % YearsPerCentury / YearsPerDecade * YearsPerDecade
}

// 获取当前年
// get Year data
func (this Datebin) Year() int {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).Year()
}

// 获取 ISO 当前年
// get ISOYear data
func (this Datebin) ISOYear() int {
	if this.IsInvalid() {
		return 0
	}

	year, _ := this.time.In(this.loc).ISOWeek()
	return year
}

// 获取当前季度
// get Quarter data
func (this Datebin) Quarter() (quarter int) {
	if this.IsInvalid() {
		return 0
	}

	// 月份
	month := this.Month()

	switch {
	case month >= 10:
		quarter = 4
	case month >= 7:
		quarter = 3
	case month >= 4:
		quarter = 2
	case month >= 1:
		quarter = 1
	}

	return
}

// 获取当前月
// get Month data
func (this Datebin) Month() int {
	if this.IsInvalid() {
		return 0
	}

	return int(this.time.In(this.loc).Month())
}

// 获取星期几数字
// get Weekday data
func (this Datebin) Weekday() int {
	if this.IsInvalid() {
		return 0
	}

	return int(this.time.In(this.loc).Weekday())
}

// 获取 ISO 星期几数字
// get ISOWeek data
func (this Datebin) ISOWeek() int {
	if this.IsInvalid() {
		return 0
	}

	_, week := this.time.In(this.loc).ISOWeek()
	return week
}

// 获取当前日
// get Day data
func (this Datebin) Day() int {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).Day()
}

// 获取当前小时
// get Hour data
func (this Datebin) Hour() int {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).Hour()
}

// 获取当前分钟数
// get Minute data
func (this Datebin) Minute() int {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).Minute()
}

// 获取当前秒数
// get Second data
func (this Datebin) Second() int {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).Second()
}

// 获取当前毫秒数，范围[0, 999]
// get Millisecond data, range [0, 999]
func (this Datebin) Millisecond() int {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).Nanosecond() / int(Millisecond)
}

// 获取当前微秒数，范围[0, 999999]
// get Microsecond data, range [0, 999999]
func (this Datebin) Microsecond() int {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).Nanosecond() / int(Microsecond)
}

// 获取当前纳秒数，范围[0, 999999999]
// get Nanosecond data, range [0, 999999999]
func (this Datebin) Nanosecond() int {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).Nanosecond()
}

// 秒级时间戳，10位
// get Timestamp data, 10 length
func (this Datebin) Timestamp() int64 {
	return this.TimestampWithSecond()
}

// 秒级时间戳，10位
// get Timestamp data, 10 length
func (this Datebin) TimestampWithSecond() int64 {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).Unix()
}

// 毫秒级时间戳，13位
// get Timestamp With Millisecond data, 13 length
func (this Datebin) TimestampWithMillisecond() int64 {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).UnixNano() / int64(Millisecond)
}

// 微秒级时间戳，16位
// get Timestamp With Microsecond data, 16 length
func (this Datebin) TimestampWithMicrosecond() int64 {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).UnixNano() / int64(Microsecond)
}

// 纳秒级时间戳，19位
// get Timestamp With Nanosecond data, 19 length
func (this Datebin) TimestampWithNanosecond() int64 {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).UnixNano()
}
