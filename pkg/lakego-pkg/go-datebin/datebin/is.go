package datebin

import (
	"fmt"
	"time"
)

// 是否是零值时间
// if the time is Zero time ?
func (this Datebin) IsZero() bool {
	return this.time.IsZero()
}

// 是否是无效时间
// if the time is Invalid time ?
func (this Datebin) IsInvalid() bool {
	if this.Error() != nil || this.IsZero() {
		return true
	}

	return false
}

// 是否是夏令时
// if the time is DST timezone ?
// IsDST reports whether the time in the configured location is in Daylight Savings Time.
func (this Datebin) IsDST() bool {
	if this.IsInvalid() {
		return false
	}

	return this.time.IsDST()
}

// 是否是 Utc 时区
// if the time is Utc timezone ?
func (this Datebin) IsUTC() bool {
	if this.IsInvalid() {
		return false
	}

	return this.GetTimezone() == UTC
}

// 是否是本地时区
// if the time is Local timezone ?
func (this Datebin) IsLocal() bool {
	if this.IsInvalid() {
		return false
	}

	return this.GetTimezone() == this.Now().GetTimezone()
}

// 是否是上午
// if the time is AM ?
func (this Datebin) IsAM() bool {
	if this.IsInvalid() {
		return false
	}

	return this.Hour() < 12
}

// 是否是下午
// if the time is PM ?
func (this Datebin) IsPM() bool {
	if this.IsInvalid() {
		return false
	}

	return this.Hour() >= 12
}

// 是否是当前时间
// if the time is Now time ?
func (this Datebin) IsNow() bool {
	if this.IsInvalid() {
		return false
	}

	return this.Timestamp() == this.Now().Timestamp()
}

// 是否是未来时间
// if the time is Future time ?
func (this Datebin) IsFuture() bool {
	if this.IsInvalid() {
		return false
	}

	return this.Timestamp() > this.Now().Timestamp()
}

// 是否是过去时间
// if the time is Past time ?
func (this Datebin) IsPast() bool {
	if this.IsInvalid() {
		return false
	}

	return this.Timestamp() < this.Now().Timestamp()
}

// 是否是闰年
// if the time is LeapYear ?
func (this Datebin) IsLeapYear() bool {
	if this.IsInvalid() {
		return false
	}

	year := this.time.In(this.loc).Year()
	if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
		return true
	}

	return false
}

// 是否是长年
// if the time is LongYear ?
func (this Datebin) IsLongYear() bool {
	if this.IsInvalid() {
		return false
	}

	_, w := time.Date(this.Year(), time.December, 31, 0, 0, 0, 0, this.loc).ISOWeek()
	return w == weeksPerLongYear
}

// 是否是今天
// if the time is Today ?
func (this Datebin) IsToday() bool {
	if this.IsInvalid() {
		return false
	}

	return this.ToDateString() == this.Now().ToDateString()
}

// 是否是昨天
// if the time is Yesterday ?
func (this Datebin) IsYesterday() bool {
	if this.IsInvalid() {
		return false
	}

	return this.ToDateString() == this.Now().Offset("day", -1).ToDateString()
}

// 是否是明天
// if the time is Tomorrow ?
func (this Datebin) IsTomorrow() bool {
	if this.IsInvalid() {
		return false
	}

	return this.ToDateString() == this.Now().Offset("day", +1).ToDateString()
}

// 是否是当年
// if the time is Current Year ?
func (this Datebin) IsCurrentYear() bool {
	if this.IsInvalid() {
		return false
	}

	return this.Year() == this.Now().Year()
}

// 是否是当月
// if the time is Current Month ?
func (this Datebin) IsCurrentMonth() bool {
	if this.IsInvalid() {
		return false
	}

	return this.Month() == this.Now().Month()
}

// 时间是否是当前最近的一周
// if the time is LatelyWeek ?
func (this Datebin) IsLatelyWeek() bool {
	if this.IsInvalid() {
		return false
	}

	secondsPerWeek := float64(SecondsPerWeek)
	difference := this.Now().ToStdTime().Sub(this.ToStdTime())

	if difference.Seconds() > 0 && difference.Seconds() < secondsPerWeek {
		return true
	}

	return false
}

// 时间是否是当前最近的一个月
// if the time is Lately Month ?
func (this Datebin) IsLatelyMonth() bool {
	if this.IsInvalid() {
		return false
	}

	now := this.Now()

	if (now.Month() == 1 && this.Month() == 12) ||
		(now.Month() == 12 && this.Month() == 1) {
		return true
	}

	monthDifference := now.Month() - this.Month()
	if absFormat(int64(monthDifference)) != 1 {
		return false
	}

	return true
}

// 是否是当前月最后一天
// if the time is Month's Last day ?
func (this Datebin) IsLastOfMonth() bool {
	if this.IsInvalid() {
		return false
	}

	return this.DayOfMonth() == this.DaysInMonth()
}

// 是否当天开始
// if the time is start of day ?
func (this Datebin) IsStartOfDay() bool {
	if this.IsInvalid() {
		return false
	}

	return this.Format("H:i:s") == "00:00:00"
}

// 是否当天开始带微妙
// if the time is start of day with microsecond ?
func (this Datebin) IsStartOfDayWithMicrosecond() bool {
	if this.IsInvalid() {
		return false
	}

	return this.Format("H:i:s") == "00:00:00" &&
		this.Microsecond() == 0
}

// 是否当天结束
// if the time is day end time ?
func (this Datebin) IsEndOfDay() bool {
	if this.IsInvalid() {
		return false
	}

	return this.Format("H:i:s") == "23:59:59"
}

// 是否当天结束带微妙
// if the time is end of day with microsecond ?
func (this Datebin) IsEndOfDayWithMicrosecond() bool {
	if this.IsInvalid() {
		return false
	}

	return this.Format("H:i:s") == "23:59:59" &&
		this.Microsecond() == 999999
}

// 是否是半夜
// if the time is midnight time ?
func (this Datebin) IsMidnight() bool {
	return this.IsStartOfDay()
}

// 是否是中午
// if the time is midday time ?
func (this Datebin) IsMidday(midDay ...string) bool {
	if this.IsInvalid() {
		return false
	}

	midDayAt := "12"
	if len(midDay) > 0 {
		midDayAt = midDay[0]
	}

	return this.Format("H:i:s") == fmt.Sprintf("%s:00:00", midDayAt)
}
