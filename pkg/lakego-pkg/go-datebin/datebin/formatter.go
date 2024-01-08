package datebin

/**
 * 格式化时间
 *
 * @create 2022-12-11
 * @author deatil
 */
type Formatter struct {
	// 传入的时间
	time int64
}

// 构造函数
func NewFormatter() Formatter {
	return Formatter{}
}

// 设置时间
func (this Formatter) WithTime(data int64) Formatter {
	this.time = data

	return this
}

// 获取时间
func (this Formatter) GetTime() int64 {
	return this.time
}

// 传入周
func (this Formatter) FromWeek(data int64) Formatter {
	this.time = data * int64(Day) * 7

	return this
}

// 传入天
func (this Formatter) FromDay(data int64) Formatter {
	this.time = data * int64(Day)

	return this
}

// 传入小时
func (this Formatter) FromHour(data int64) Formatter {
	this.time = data * int64(Hour)

	return this
}

// 传入分钟
func (this Formatter) FromMinute(data int64) Formatter {
	this.time = data * int64(Minute)

	return this
}

// 传入秒
func (this Formatter) FromSecond(data int64) Formatter {
	this.time = data * int64(Second)

	return this
}

// 传入毫秒
func (this Formatter) FromMillisecond(data int64) Formatter {
	this.time = data * int64(Millisecond)

	return this
}

// 传入微秒
func (this Formatter) FromMicrosecond(data int64) Formatter {
	this.time = data * int64(Microsecond)

	return this
}

// 传入纳秒
func (this Formatter) FromNanosecond(data int64) Formatter {
	this.time = data

	return this
}

// 获取周数和天数
func (this Formatter) WeekAndDay() (int, int) {
	weeks := this.time / int64(Week)
	days := (this.time % int64(Week)) / int64(Day)

	return int(weeks), int(days)
}

// 获取天
func (this Formatter) Day() int {
	data := this.time / int64(Day)

	return int(data)
}

// 获取小时
func (this Formatter) Hour() int {
	data := (this.time % int64(Day)) / int64(Hour)

	return int(data)
}

// 获取分钟
func (this Formatter) Minute() int {
	data := (this.time % int64(Hour)) / int64(Minute)

	return int(data)
}

// 获取秒
func (this Formatter) Second() int {
	data := (this.time % int64(Minute)) / int64(Second)

	return int(data)
}

// 获取毫秒
func (this Formatter) Millisecond() int {
	data := (this.time % int64(Second)) / int64(Millisecond)

	return int(data)
}

// 获取微秒
func (this Formatter) Microsecond() int {
	data := (this.time % int64(Millisecond)) / int64(Microsecond)

	return int(data)
}

// 获取纳秒
func (this Formatter) Nanosecond() int {
	// 余数
	data := this.time % int64(Microsecond)

	return int(data)
}
