package datebin

// 获取当前世纪
func (this Datebin) Century() int {
	if this.IsInvalid() {
		return 0
	}

	return this.Year()/YearsPerCentury + 1
}

// 获取当前年代
func (this Datebin) Decade() int {
	if this.IsInvalid() {
		return 0
	}

	return this.Year() % YearsPerCentury / YearsPerDecade * YearsPerDecade
}

// 获取当前年
func (this Datebin) Year() int {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).Year()
}

// 获取当前季度
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
func (this Datebin) Month() int {
	if this.IsInvalid() {
		return 0
	}

	return int(this.time.In(this.loc).Month())
}

// 星期几数字
func (this Datebin) Weekday() int {
	if this.IsInvalid() {
		return 0
	}

	return int(this.time.In(this.loc).Weekday())
}

// 获取当前日
func (this Datebin) Day() int {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).Day()
}

// 获取当前小时
func (this Datebin) Hour() int {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).Hour()
}

// 获取当前分钟数
func (this Datebin) Minute() int {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).Minute()
}

// 获取当前秒数
func (this Datebin) Second() int {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).Second()
}

// 获取当前毫秒数，范围[0, 999]
func (this Datebin) Millisecond() int {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).Nanosecond() / int(Millisecond)
}

// 获取当前微秒数，范围[0, 999999]
func (this Datebin) Microsecond() int {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).Nanosecond() / int(Microsecond)
}

// 获取当前纳秒数，范围[0, 999999999]
func (this Datebin) Nanosecond() int {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).Nanosecond()
}

// 秒级时间戳，10位
func (this Datebin) Timestamp() int64 {
	return this.TimestampWithSecond()
}

// 秒级时间戳，10位
func (this Datebin) TimestampWithSecond() int64 {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).Unix()
}

// 毫秒级时间戳，13位
func (this Datebin) TimestampWithMillisecond() int64 {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).UnixNano() / int64(Millisecond)
}

// 微秒级时间戳，16位
func (this Datebin) TimestampWithMicrosecond() int64 {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).UnixNano() / int64(Microsecond)
}

// 纳秒级时间戳，19位
func (this Datebin) TimestampWithNanosecond() int64 {
	if this.IsInvalid() {
		return 0
	}

	return this.time.In(this.loc).UnixNano()
}
