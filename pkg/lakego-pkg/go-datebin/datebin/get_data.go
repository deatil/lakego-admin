package datebin

// 返回年月日数据
// get year, month, day data
func (this Datebin) Date() (year, month, day int) {
	if this.IsInvalid() {
		return
	}

	year, timeMonth, day := this.time.In(this.loc).Date()

	return year, int(timeMonth), day
}

// 返回时分秒数据
// get hour, minute, second data
func (this Datebin) Time() (hour, minute, second int) {
	if this.IsInvalid() {
		return
	}

	return this.time.In(this.loc).Clock()
}

// 返回年月日时分秒数据
// get year, month, day, hour, minute, second data
func (this Datebin) Datetime() (year, month, day, hour, minute, second int) {
	if this.IsInvalid() {
		return
	}

	year, month, day = this.Date()
	hour, minute, second = this.Time()

	return
}

// 返回年月日时分秒数据带纳秒
// get year, month, day, hour, minute, second, nanosecond data
func (this Datebin) DatetimeWithNanosecond() (year, month, day, hour, minute, second, nanosecond int) {
	if this.IsInvalid() {
		return
	}

	year, month, day, hour, minute, second = this.Datetime()
	nanosecond = this.Nanosecond()

	return
}

// 返回年月日时分秒数据带微秒
// get year, month, day, hour, minute, second, microsecond data
func (this Datebin) DatetimeWithMicrosecond() (year, month, day, hour, minute, second, microsecond int) {
	if this.IsInvalid() {
		return
	}

	year, month, day, hour, minute, second = this.Datetime()
	microsecond = this.Microsecond()

	return
}

// 返回年月日时分秒数据带毫秒
// get year, month, day, hour, minute, second, millisecond data
func (this Datebin) DatetimeWithMillisecond() (year, month, day, hour, minute, second, millisecond int) {
	if this.IsInvalid() {
		return
	}

	year, month, day, hour, minute, second = this.Datetime()
	millisecond = this.Millisecond()

	return
}
