package datebin

import (
	"time"
)

// 当前
// now time
func (this Datebin) Now(timezone ...string) Datebin {
	if len(timezone) > 0 {
		this = this.SetTimezone(timezone[0])
	}

	this.time = time.Now().In(this.loc)
	return this
}

// 当前
// now time
func Now(timezone ...string) Datebin {
	return defaultDatebin.Now(timezone...)
}

// 今天
// Today
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
// Today
func Today(timezone ...string) Datebin {
	return defaultDatebin.Today(timezone...)
}

// 明天
// Tomorrow
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
// Tomorrow
func Tomorrow(timezone ...string) Datebin {
	return defaultDatebin.Tomorrow(timezone...)
}

// 昨天
// Yesterday
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
// Yesterday
func Yesterday(timezone ...string) Datebin {
	return defaultDatebin.Yesterday(timezone...)
}

// 最小值
// Min
func (this Datebin) Min(d Datebin) Datebin {
	if this.Lt(d) {
		return this
	}

	return d
}

// 最小值
// Minimum
func (this Datebin) Minimum(d Datebin) Datebin {
	return this.Min(d)
}

// 最大值
// Max
func (this Datebin) Max(d Datebin) Datebin {
	if this.Gt(d) {
		return this
	}

	return d
}

// 最大值
// Maximum
func (this Datebin) Maximum(d Datebin) Datebin {
	return this.Max(d)
}

// 平均值
// Avg
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
// Average
func (this Datebin) Average(d Datebin) Datebin {
	return this.Avg(d)
}

// 取 a 和 b 中与当前时间最近的一个
// Closest
func (this Datebin) Closest(a Datebin, b Datebin) Datebin {
	if this.Diff(a).SecondsAbs() < this.Diff(b).SecondsAbs() {
		return a
	}

	return b
}

// 取 a 和 b 中与当前时间最远的一个
// Farthest
func (this Datebin) Farthest(a Datebin, b Datebin) Datebin {
	if this.Diff(a).SecondsAbs() > this.Diff(b).SecondsAbs() {
		return a
	}

	return b
}

// 年龄，可为负数
// Age
func (this Datebin) Age() int {
	if this.IsInvalid() {
		return 0
	}

	return int(this.Diff(this.Now()).Years())
}

// 用于查找将规定的持续时间 'd' 舍入为 'm' 持续时间的最接近倍数的结果
// Round
func (this Datebin) Round(d time.Duration) Datebin {
	this.time = this.time.Round(d)
	return this
}

// 用于查找将规定的持续时间 'd' 朝零舍入到 'm' 持续时间的倍数的结果
// Truncate
func (this Datebin) Truncate(d time.Duration) Datebin {
	this.time = this.time.Truncate(d)
	return this
}
