package datebin

import (
    "time"
)

// 是否是春季
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
func (this Datebin) IsJanuary() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.January
}

// 是否是二月
func (this Datebin) IsFebruary() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.February
}

// 是否是三月
func (this Datebin) IsMarch() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.March
}

// 是否是四月
func (this Datebin) IsApril() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.April
}

// 是否是五月
func (this Datebin) IsMay() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.May
}

// 是否是六月
func (this Datebin) IsJune() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.June
}

// 是否是七月
func (this Datebin) IsJuly() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.July
}

// 是否是八月
func (this Datebin) IsAugust() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.August
}

// 是否是九月
func (this Datebin) IsSeptember() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.September
}

// 是否是十月
func (this Datebin) IsOctober() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.October
}

// 是否是十一月
func (this Datebin) IsNovember() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.November
}

// 是否是十二月
func (this Datebin) IsDecember() bool {
    if this.IsInvalid() {
        return false
    }

    return this.time.In(this.loc).Month() == time.December
}
