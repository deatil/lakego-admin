package time

// 大于
func (this Datebin) Gt(d Datebin) bool {
    return this.time.After(d.time)
}

// 小于
func (this Datebin) Lt(d Datebin) bool {
    return this.time.Before(d.time)
}

// 等于
func (this Datebin) Eq(d Datebin) bool {
    return this.time.Equal(d.time)
}

// 不等于
func (this Datebin) Ne(d Datebin) bool {
    return !this.Eq(d)
}

// 大于等于
func (this Datebin) Gte(d Datebin) bool {
    return this.Gt(d) || this.Eq(d)
}

// 小于等于
func (this Datebin) Lte(d Datebin) bool {
    return this.Lt(d) || this.Eq(d)
}

// 是否在两个时间之间(不包括这两个时间)
func (this Datebin) Between(start Datebin, end Datebin) bool {
    if this.Gt(start) && this.Lt(end) {
        return true
    }

    return false
}

// 是否在两个时间之间(包括这两个时间)
func (this Datebin) BetweenIncluded(start Datebin, end Datebin) bool {
    if this.Gte(start) && this.Lte(end) {
        return true
    }

    return false
}

// 是否在两个时间之间(包括开始时间)
func (this Datebin) BetweenIncludStart(start Datebin, end Datebin) bool {
    if this.Gte(start) && this.Lt(end) {
        return true
    }

    return false
}

// 是否在两个时间之间(包括结束时间)
func (this Datebin) BetweenIncludEnd(start Datebin, end Datebin) bool {
    if this.Gt(start) && this.Lte(end) {
        return true
    }

    return false
}
