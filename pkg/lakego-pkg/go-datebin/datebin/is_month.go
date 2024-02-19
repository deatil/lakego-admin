package datebin

import (
	"time"
)

// 是否是春季
// if the time is Spring ?
func (this Datebin) IsSpring() bool {
	if this.IsInvalid() {
		return false
	}

	if this.Month() == 3 || this.Month() == 4 || this.Month() == 5 {
		return true
	}

	return false
}

// 是否是夏季
// if the time is Summer ?
func (this Datebin) IsSummer() bool {
	if this.IsInvalid() {
		return false
	}

	if this.Month() == 6 || this.Month() == 7 || this.Month() == 8 {
		return true
	}

	return false
}

// 是否是秋季
// if the time is Autumn ?
func (this Datebin) IsAutumn() bool {
	if this.IsInvalid() {
		return false
	}

	if this.Month() == 9 || this.Month() == 10 || this.Month() == 11 {
		return true
	}

	return false
}

// 是否是冬季
// if the time is Winter ?
func (this Datebin) IsWinter() bool {
	if this.IsInvalid() {
		return false
	}

	if this.Month() == 12 || this.Month() == 1 || this.Month() == 2 {
		return true
	}

	return false
}

// 是否是一月
// if the time is January ?
func (this Datebin) IsJanuary() bool {
	if this.IsInvalid() {
		return false
	}

	return this.time.In(this.loc).Month() == time.January
}

// 是否是二月
// if the time is February ?
func (this Datebin) IsFebruary() bool {
	if this.IsInvalid() {
		return false
	}

	return this.time.In(this.loc).Month() == time.February
}

// 是否是三月
// if the time is March ?
func (this Datebin) IsMarch() bool {
	if this.IsInvalid() {
		return false
	}

	return this.time.In(this.loc).Month() == time.March
}

// 是否是四月
// if the time is April ?
func (this Datebin) IsApril() bool {
	if this.IsInvalid() {
		return false
	}

	return this.time.In(this.loc).Month() == time.April
}

// 是否是五月
// if the time is May ?
func (this Datebin) IsMay() bool {
	if this.IsInvalid() {
		return false
	}

	return this.time.In(this.loc).Month() == time.May
}

// 是否是六月
// if the time is June ?
func (this Datebin) IsJune() bool {
	if this.IsInvalid() {
		return false
	}

	return this.time.In(this.loc).Month() == time.June
}

// 是否是七月
// if the time is July ?
func (this Datebin) IsJuly() bool {
	if this.IsInvalid() {
		return false
	}

	return this.time.In(this.loc).Month() == time.July
}

// 是否是八月
// if the time is August ?
func (this Datebin) IsAugust() bool {
	if this.IsInvalid() {
		return false
	}

	return this.time.In(this.loc).Month() == time.August
}

// 是否是九月
// if the time is September ?
func (this Datebin) IsSeptember() bool {
	if this.IsInvalid() {
		return false
	}

	return this.time.In(this.loc).Month() == time.September
}

// 是否是十月
// if the time is October ?
func (this Datebin) IsOctober() bool {
	if this.IsInvalid() {
		return false
	}

	return this.time.In(this.loc).Month() == time.October
}

// 是否是十一月
// if the time is November ?
func (this Datebin) IsNovember() bool {
	if this.IsInvalid() {
		return false
	}

	return this.time.In(this.loc).Month() == time.November
}

// 是否是十二月
// if the time is December ?
func (this Datebin) IsDecember() bool {
	if this.IsInvalid() {
		return false
	}

	return this.time.In(this.loc).Month() == time.December
}
