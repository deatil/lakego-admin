package datebin

import (
	"time"
)

// 输入标准时间
// create from std time
func (this Datebin) FromStdTime(t time.Time, timezone ...string) Datebin {
	this.time = t
	this.loc = t.Location()

	if len(timezone) > 0 {
		this = this.SetTimezone(timezone[0])
	}

	return this
}

// 输入标准时间
// create from std time
func FromStdTime(t time.Time, timezone ...string) Datebin {
	return defaultDatebin.FromStdTime(t, timezone...)
}

// 输入标准时间戳带毫秒
// create from std unix
func (this Datebin) FromStdUnix(second int64, nsec int64, timezone ...string) Datebin {
	return this.FromStdTime(time.Unix(second, nsec), timezone...)
}

// 输入标准时间戳带毫秒
// create from std unix
func FromStdUnix(second int64, nsec int64, timezone ...string) Datebin {
	return defaultDatebin.FromStdUnix(second, nsec, timezone...)
}

// 输入时间戳
// create from std timestamp
func (this Datebin) FromTimestamp(timestamp int64, timezone ...string) Datebin {
	return this.FromStdUnix(timestamp, 0, timezone...)
}

// 输入时间戳
// create from std timestamp
func FromTimestamp(timestamp int64, timezone ...string) Datebin {
	return defaultDatebin.FromTimestamp(timestamp, timezone...)
}

// 输入日期时间带纳秒
// create from date_time with nanosecond
func (this Datebin) FromDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond int, timezone ...string) Datebin {
	monthData, ok := Months[month]
	if !ok {
		monthData = Months[1]
	}

	return this.FromStdTime(time.Date(year, monthData, day, hour, minute, second, nanosecond, time.Local), timezone...)
}

// 输入日期时间带纳秒
// create from date_time with nanosecond
func FromDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond int, timezone ...string) Datebin {
	return defaultDatebin.FromDatetimeWithNanosecond(year, month, day, hour, minute, second, nanosecond, timezone...)
}

// 输入日期时间带微秒
// create from date_time with microsecond
func (this Datebin) FromDatetimeWithMicrosecond(year, month, day, hour, minute, second, microsecond int, timezone ...string) Datebin {
	return this.FromDatetimeWithNanosecond(year, month, day, hour, minute, second, microsecond*1e3, timezone...)
}

// 输入日期时间带微秒
// create from date_time with microsecond
func FromDatetimeWithMicrosecond(year, month, day, hour, minute, second, microsecond int, timezone ...string) Datebin {
	return defaultDatebin.FromDatetimeWithMicrosecond(year, month, day, hour, minute, second, microsecond, timezone...)
}

// 输入日期时间带毫秒
// create from date_time with millisecond
func (this Datebin) FromDatetimeWithMillisecond(year, month, day, hour, minute, second, millisecond int, timezone ...string) Datebin {
	return this.FromDatetimeWithNanosecond(year, month, day, hour, minute, second, millisecond*1e6, timezone...)
}

// 输入日期时间带毫秒
// create from date_time with millisecond
func FromDatetimeWithMillisecond(year, month, day, hour, minute, second, millisecond int, timezone ...string) Datebin {
	return defaultDatebin.FromDatetimeWithMillisecond(year, month, day, hour, minute, second, millisecond, timezone...)
}

// 输入日期和时间
// create from date_time
func (this Datebin) FromDatetime(year, month, day, hour, minute, second int, timezone ...string) Datebin {
	return this.FromDatetimeWithNanosecond(year, month, day, hour, minute, second, 0, timezone...)
}

// 输入日期和时间
// create from date_time
func FromDatetime(year, month, day, hour, minute, second int, timezone ...string) Datebin {
	return defaultDatebin.FromDatetime(year, month, day, hour, minute, second, timezone...)
}

// 输入日期
// create from date
func (this Datebin) FromDate(year, month, day int, timezone ...string) Datebin {
	return this.FromDatetimeWithNanosecond(year, month, day, 0, 0, 0, 0, timezone...)
}

// 输入日期
// create from date
func FromDate(year, month, day int, timezone ...string) Datebin {
	return defaultDatebin.FromDate(year, month, day, timezone...)
}

// 输入时间
// create from time
func (this Datebin) FromTime(hour, minute, second int, timezone ...string) Datebin {
	year, month, day := this.Now(timezone...).Date()

	return this.FromDatetimeWithNanosecond(year, month, day, hour, minute, second, 0, timezone...)
}

// 输入时间
// create from time
func FromTime(hour, minute, second int, timezone ...string) Datebin {
	return defaultDatebin.FromTime(hour, minute, second, timezone...)
}
