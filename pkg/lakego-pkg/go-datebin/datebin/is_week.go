package datebin

import (
	"time"
)

// 是否是周一
// if the time is Monday ?
func (this Datebin) IsMonday() bool {
	if this.IsInvalid() {
		return false
	}

	return this.time.In(this.loc).Weekday() == time.Monday
}

// 是否是周二
// if the time is Tuesday ?
func (this Datebin) IsTuesday() bool {
	if this.IsInvalid() {
		return false
	}

	return this.time.In(this.loc).Weekday() == time.Tuesday
}

// 是否是周三
// if the time is Wednesday ?
func (this Datebin) IsWednesday() bool {
	if this.IsInvalid() {
		return false
	}

	return this.time.In(this.loc).Weekday() == time.Wednesday
}

// 是否是周四
// if the time is Thursday ?
func (this Datebin) IsThursday() bool {
	if this.IsInvalid() {
		return false
	}

	return this.time.In(this.loc).Weekday() == time.Thursday
}

// 是否是周五
// if the time is Friday ?
func (this Datebin) IsFriday() bool {
	if this.IsInvalid() {
		return false
	}

	return this.time.In(this.loc).Weekday() == time.Friday
}

// 是否是周六
// if the time is Saturday ?
func (this Datebin) IsSaturday() bool {
	if this.IsInvalid() {
		return false
	}

	return this.time.In(this.loc).Weekday() == time.Saturday
}

// 是否是周日
// if the time is Sunday ?
func (this Datebin) IsSunday() bool {
	if this.IsInvalid() {
		return false
	}

	return this.time.In(this.loc).Weekday() == time.Sunday
}

// 是否是工作日
// if the time is Weekday ?
func (this Datebin) IsWeekday() bool {
	if this.IsInvalid() {
		return false
	}

	return !this.IsSaturday() && !this.IsSunday()
}

// 是否是周末
// if the time is Weekend ?
func (this Datebin) IsWeekend() bool {
	if this.IsInvalid() {
		return false
	}

	return this.IsSaturday() || this.IsSunday()
}
