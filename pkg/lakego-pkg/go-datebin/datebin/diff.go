package datebin

// 相差时间判断
// get DiffTime struct
func (this Datebin) Diff(date Datebin) DiffTime {
	return NewDiffTime(this, date)
}
