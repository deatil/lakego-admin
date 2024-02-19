package datebin

/**
 * 格式化时间 / Formatter time
 *
 * @create 2022-12-11
 * @author deatil
 */
type Formatter struct {
	// 传入的时间 / input time
	time int64
}

// 构造函数
// New Formatter
func NewFormatter() Formatter {
	return Formatter{}
}

// 设置时间
// set Time
func (this Formatter) WithTime(data int64) Formatter {
	this.time = data

	return this
}

// 获取时间
// Get Time
func (this Formatter) GetTime() int64 {
	return this.time
}

// 传入周
// set Week
func (this Formatter) FromWeek(data int64) Formatter {
	this.time = data * int64(Day) * 7

	return this
}

// 传入天
// set Day
func (this Formatter) FromDay(data int64) Formatter {
	this.time = data * int64(Day)

	return this
}

// 传入小时
// set Hour
func (this Formatter) FromHour(data int64) Formatter {
	this.time = data * int64(Hour)

	return this
}

// 传入分钟
// set Minute
func (this Formatter) FromMinute(data int64) Formatter {
	this.time = data * int64(Minute)

	return this
}

// 传入秒
// set Second
func (this Formatter) FromSecond(data int64) Formatter {
	this.time = data * int64(Second)

	return this
}

// 传入毫秒
// set Millisecond
func (this Formatter) FromMillisecond(data int64) Formatter {
	this.time = data * int64(Millisecond)

	return this
}

// 传入微秒
// set Microsecond
func (this Formatter) FromMicrosecond(data int64) Formatter {
	this.time = data * int64(Microsecond)

	return this
}

// 传入纳秒
// set Nanosecond
func (this Formatter) FromNanosecond(data int64) Formatter {
	this.time = data

	return this
}

// 获取周数和天数
// get Week And Day
func (this Formatter) WeekAndDay() (int, int) {
	weeks := this.time / int64(Week)
	days := (this.time % int64(Week)) / int64(Day)

	return int(weeks), int(days)
}

// 获取天
// get Day
func (this Formatter) Day() int {
	data := this.time / int64(Day)

	return int(data)
}

// 获取小时
// get Hour
func (this Formatter) Hour() int {
	data := (this.time % int64(Day)) / int64(Hour)

	return int(data)
}

// 获取分钟
// get Minute
func (this Formatter) Minute() int {
	data := (this.time % int64(Hour)) / int64(Minute)

	return int(data)
}

// 获取秒
// get Second
func (this Formatter) Second() int {
	data := (this.time % int64(Minute)) / int64(Second)

	return int(data)
}

// 获取毫秒
// get Millisecond
func (this Formatter) Millisecond() int {
	data := (this.time % int64(Second)) / int64(Millisecond)

	return int(data)
}

// 获取微秒
// get Microsecond
func (this Formatter) Microsecond() int {
	data := (this.time % int64(Millisecond)) / int64(Microsecond)

	return int(data)
}

// 获取纳秒
// get Nanosecond
func (this Formatter) Nanosecond() int {
	// 余数 / mod
	data := this.time % int64(Microsecond)

	return int(data)
}
