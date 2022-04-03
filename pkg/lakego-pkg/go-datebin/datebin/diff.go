package datebin

// 相差时间判断
func (this Datebin) Diff(date Datebin) Difftime {
    return NewDifftime(this, date)
}
