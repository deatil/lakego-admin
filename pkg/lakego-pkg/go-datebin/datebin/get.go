package datebin

import (
    "time"
)

// 最小值
func (this Datebin) Min(d Datebin) Datebin {
    if this.Lt(d) {
        return this
    }

    return d
}

// 最小值
func (this Datebin) Minimum(d Datebin) Datebin {
    return this.Min(d)
}

// 最大值
func (this Datebin) Max(d Datebin) Datebin {
    if this.Gt(d) {
        return this
    }

    return d
}

// 最大值
func (this Datebin) Maximum(d Datebin) Datebin {
    return this.Max(d)
}

// 平均值
func (this Datebin) Avg(d Datebin) Datebin {
    diffSeconds := this.Diff(d).Seconds()

    if diffSeconds == 0 {
        return this
    }

    average := int(diffSeconds / 2)
    if average > 0 {
        return this.AddSeconds(uint(average))
    } else {
        return this.SubSeconds(uint(-average))
    }
}

// 平均值
func (this Datebin) Average(d Datebin) Datebin {
    return this.Avg(d)
}

// 取 a 和 b 中与当前时间最近的一个
func (this Datebin) Closest(a Datebin, b Datebin) Datebin {
    if this.Diff(a).SecondsAbs() < this.Diff(b).SecondsAbs() {
        return a
    }

    return b
}

// 取 a 和 b 中与当前时间最远的一个
func (this Datebin) Farthest(a Datebin, b Datebin) Datebin {
    if this.Diff(a).SecondsAbs() > this.Diff(b).SecondsAbs() {
        return a
    }

    return b
}

// 年龄，可为负数
func (this Datebin) Age() int {
    if this.IsInvalid() {
        return 0
    }

    return int(this.Diff(this.Now()).Years())
}

// 用于查找将规定的持续时间‘d’舍入为‘m’持续时间的最接近倍数的结果
func (this Datebin) Round(d time.Duration) Datebin {
    this.time = this.time.Round(d)
    return this
}

// 用于查找将规定的持续时间‘d’朝零舍入到‘m’持续时间的倍数的结果
func (this Datebin) Truncate(d time.Duration) Datebin {
    this.time = this.time.Truncate(d)
    return this
}
