package datebin

import (
	"time"
)

// 当前
// get Now time
func (this Datebin) Now(timezone ...string) Datebin {
	if len(timezone) > 0 {
		this = this.SetTimezone(timezone[0])
	}

	this.time = time.Now().In(this.loc)
	return this
}

// 当前
// get Now time
func Now(timezone ...string) Datebin {
	return defaultDatebin.Now(timezone...)
}

// 今天
// get Today time
func (this Datebin) Today(timezone ...string) Datebin {
	if len(timezone) > 0 {
		this = this.SetTimezone(timezone[0])
	}

	var datetime Datebin
	if this.IsZero() {
		datetime = this.Now()
	} else {
		datetime = this
	}

	this.time = time.Date(datetime.Year(), time.Month(datetime.Month()), datetime.Day(), 0, 0, 0, 0, datetime.loc)

	return this
}

// 今天
// get Today time
func Today(timezone ...string) Datebin {
	return defaultDatebin.Today(timezone...)
}

// 明天
// get Tomorrow time
func (this Datebin) Tomorrow(timezone ...string) Datebin {
	if len(timezone) > 0 {
		this = this.SetTimezone(timezone[0])
	}

	var datetime Datebin
	if this.IsZero() {
		datetime = this.Now().AddDay()
	} else {
		datetime = this.AddDay()
	}

	this.time = time.Date(datetime.Year(), time.Month(datetime.Month()), datetime.Day(), 0, 0, 0, 0, datetime.loc)

	return this
}

// 明天
// get Tomorrow time
func Tomorrow(timezone ...string) Datebin {
	return defaultDatebin.Tomorrow(timezone...)
}

// 昨天
// get Yesterday time
func (this Datebin) Yesterday(timezone ...string) Datebin {
	if len(timezone) > 0 {
		this = this.SetTimezone(timezone[0])
	}

	var datetime Datebin
	if this.IsZero() {
		datetime = this.Now().SubDay()
	} else {
		datetime = this.SubDay()
	}

	this.time = time.Date(datetime.Year(), time.Month(datetime.Month()), datetime.Day(), 0, 0, 0, 0, datetime.loc)

	return this
}

// 昨天
// get Yesterday time
func Yesterday(timezone ...string) Datebin {
	return defaultDatebin.Yesterday(timezone...)
}

// 最小值
// get a Minimum time from a and b
func (this Datebin) Min(d Datebin) Datebin {
	if this.Lt(d) {
		return this
	}

	return d
}

// 最小值
// get a Minimum time from a and b
func (this Datebin) Minimum(d Datebin) Datebin {
	return this.Min(d)
}

// 最大值
// get a Maximum time from a and b
func (this Datebin) Max(d Datebin) Datebin {
	if this.Gt(d) {
		return this
	}

	return d
}

// 最大值
// get a Maximum time from a and b
func (this Datebin) Maximum(d Datebin) Datebin {
	return this.Max(d)
}

// 平均值
// get a Average time from a and b
func (this Datebin) Avg(d Datebin) Datebin {
	diffSeconds := this.Diff(d).Seconds()

	if diffSeconds == 0 {
		return this
	}

	average := int(diffSeconds / 2)
	if average > 0 {
		return this.AddSeconds(uint(average))
	} else {
		return this.SubSeconds(uint(-average))
	}
}

// 平均值
// get a Average time from a and b
func (this Datebin) Average(d Datebin) Datebin {
	return this.Avg(d)
}

// 取 a 和 b 中与当前时间最近的一个
// get a Closest time from a and b
func (this Datebin) Closest(a Datebin, b Datebin) Datebin {
	if this.Diff(a).SecondsAbs() < this.Diff(b).SecondsAbs() {
		return a
	}

	return b
}

// 取 a 和 b 中与当前时间最远的一个
// get a Farthest time from a and b
func (this Datebin) Farthest(a Datebin, b Datebin) Datebin {
	if this.Diff(a).SecondsAbs() > this.Diff(b).SecondsAbs() {
		return a
	}

	return b
}

// 年龄，可为负数
// get Age data
func (this Datebin) Age() int {
	if this.IsInvalid() {
		return 0
	}

	return int(this.Diff(this.Now()).Years())
}

// 用于查找将规定的持续时间 'd' 舍入为 'm' 持续时间的最接近倍数的结果
// Round returns the result of rounding t to the nearest multiple of d (since the zero time).
// The rounding behavior for halfway values is to round up.
// If d <= 0, Round returns t stripped of any monotonic clock reading but otherwise unchanged.
//
// Round operates on the time as an absolute duration since the
// zero time; it does not operate on the presentation form of the
// time. Thus, Round(Hour) may return a time with a non-zero
// minute, depending on the time's Location.
func (this Datebin) Round(d time.Duration) Datebin {
	this.time = this.time.Round(d)
	return this
}

// 用于查找将规定的持续时间 'd' 朝零舍入到 'm' 持续时间的倍数的结果
// Truncate returns the result of rounding d toward zero to a multiple of m.
// If m <= 0, Truncate returns d unchanged.
func (this Datebin) Truncate(d time.Duration) Datebin {
	this.time = this.time.Truncate(d)
	return this
}
