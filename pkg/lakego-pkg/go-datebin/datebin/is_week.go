package datebin

import (
    "time"
)

// 是否是周一
func (this Datebin) IsMonday() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Weekday() == time.Monday
}

// 是否是周二
func (this Datebin) IsTuesday() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Weekday() == time.Tuesday
}

// 是否是周三
func (this Datebin) IsWednesday() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Weekday() == time.Wednesday
}

// 是否是周四
func (this Datebin) IsThursday() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Weekday() == time.Thursday
}

// 是否是周五
func (this Datebin) IsFriday() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Weekday() == time.Friday
}

// 是否是周六
func (this Datebin) IsSaturday() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Weekday() == time.Saturday
}

// 是否是周日
func (this Datebin) IsSunday() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Weekday() == time.Sunday
}

// 是否是工作日
func (this Datebin) IsWeekday() bool {
    if this.IsInvalid() {
        return false
    }

    return !this.IsSaturday() && !this.IsSunday()
}

// 是否是周末
func (this Datebin) IsWeekend() bool {
    if this.IsInvalid() {
        return false
    }

    return this.IsSaturday() || this.IsSunday()
}
