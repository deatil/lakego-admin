package datebin

// 判断判断 a 大于 d
// if a Gt d
func (this Datebin) Gt(d Datebin) bool {
	return this.time.After(d.time)
}

// 判断判断 a 小于 d
// if a Lt d
func (this Datebin) Lt(d Datebin) bool {
	return this.time.Before(d.time)
}

// 判断判断 a 等于 d
// if a Eq d
func (this Datebin) Eq(d Datebin) bool {
	return this.time.Equal(d.time)
}

// 判断判断 a 不等于 d
// if a Ne d
func (this Datebin) Ne(d Datebin) bool {
	return !this.Eq(d)
}

// 判断判断 a 大于等于 d
// if a Gte d
func (this Datebin) Gte(d Datebin) bool {
	return this.Gt(d) || this.Eq(d)
}

// 判断判断 a 小于等于 d
// if a Lte d
func (this Datebin) Lte(d Datebin) bool {
	return this.Lt(d) || this.Eq(d)
}

// 是否在两个时间之间(不包括这两个时间)
// if a Between start and end
func (this Datebin) Between(start Datebin, end Datebin) bool {
	if this.Gt(start) && this.Lt(end) {
		return true
	}

	return false
}

// 是否在两个时间之间(包括这两个时间)
// if a BetweenIncluded start and end
func (this Datebin) BetweenIncluded(start Datebin, end Datebin) bool {
	if this.Gte(start) && this.Lte(end) {
		return true
	}

	return false
}

// 是否在两个时间之间(包括开始时间)
// if a BetweenIncludStart start and end
func (this Datebin) BetweenIncludStart(start Datebin, end Datebin) bool {
	if this.Gte(start) && this.Lt(end) {
		return true
	}

	return false
}

// 是否在两个时间之间(包括结束时间)
// if a BetweenIncludEnd start and end
func (this Datebin) BetweenIncludEnd(start Datebin, end Datebin) bool {
	if this.Gt(start) && this.Lte(end) {
		return true
	}

	return false
}
