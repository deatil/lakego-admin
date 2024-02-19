package datetimes

import (
	"github.com/deatil/go-datebin/datebin"
)

/**
 * 时间范围 / Datetimes
 *
 * @create 2024-1-6
 * @author deatil
 */
type Datetimes struct {
	// 开始时间 / start time
	Start datebin.Datebin

	// 结束时间 / end time
	End datebin.Datebin
}

// New Datetimes
func NewDatetimes(start, end datebin.Datebin) Datetimes {
	if start.Gt(end) {
		start, end = end, start
	}

	return Datetimes{
		Start: start,
		End:   end,
	}
}

// New Datetimes
func New(start, end datebin.Datebin) Datetimes {
	return NewDatetimes(start, end)
}

// 获取交集数据
// get Intersection times
func (this Datetimes) Intersection(x Datetimes) Datetimes {
	ds := Datetimes{}

	left, right := this.swap(this, x)

	if left.Start.Lt(right.Start) {
		ds.Start = right.Start
	} else {
		ds.Start = left.Start
	}

	if left.End.Gt(right.End) {
		ds.End = right.End
	} else {
		ds.End = left.End
	}

	return ds
}

// 获取并集数据
// get Union times
func (this Datetimes) Union(x Datetimes) []Datetimes {
	ds := make([]Datetimes, 0)

	left, right := this.swap(this, x)

	if left.End.Lt(right.Start) {
		ds = append(ds, left)
		ds = append(ds, right)
	} else {
		ds = append(ds, Datetimes{
			Start: left.Start,
			End:   right.End,
		})
	}

	return ds
}

// a 是否包含 x
// if a is Contain x
func (this Datetimes) IsContain(x Datetimes) bool {
	if this.Start.Gt(x.Start) {
		return false
	}

	if this.End.Lt(x.End) {
		return false
	}

	return true
}

// 交换大小
// swap x, y
func (this Datetimes) swap(x, y Datetimes) (Datetimes, Datetimes) {
	left, right := x, y

	if left.Start.Gt(right.Start) {
		left, right = right, left
	}

	return left, right
}

// 获取范围长度
// get Length
func (this Datetimes) Length() int64 {
	return this.End.Timestamp() - this.Start.Timestamp()
}

// 获取范围长度带纳米
// get Length With Nanosecond
func (this Datetimes) LengthWithNanosecond() int64 {
	return this.End.TimestampWithNanosecond() - this.Start.TimestampWithNanosecond()
}

// a 是否大于 d
// if a gt d
func (this Datetimes) Gt(d Datetimes) bool {
	return this.LengthWithNanosecond() > d.LengthWithNanosecond()
}

// a 是否小于 d
// if a Lt d
func (this Datetimes) Lt(d Datetimes) bool {
	return this.LengthWithNanosecond() < d.LengthWithNanosecond()
}

// a 是否等于 d
// if a eq d
func (this Datetimes) Eq(d Datetimes) bool {
	return this.LengthWithNanosecond() == d.LengthWithNanosecond()
}

// a 是否不等于 d
// if a Not eq d
func (this Datetimes) Ne(d Datetimes) bool {
	return !this.Eq(d)
}

// a 是否大于等于 d
// if a Gte d
func (this Datetimes) Gte(d Datetimes) bool {
	return this.Gt(d) || this.Eq(d)
}

// a 是否小于等于 d
// if a Lte d
func (this Datetimes) Lte(d Datetimes) bool {
	return this.Lt(d) || this.Eq(d)
}
