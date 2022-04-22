package datebin

// 相差时间判断
func (this Datebin) Diff(date Datebin) Difftime {
    // 时区设置为同一时区
    this.time = this.time.In(this.loc)

    date.time = date.time.In(this.loc)

    return NewDifftime(this, date)
}
