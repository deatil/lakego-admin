package datebin

// 取绝对值
func absFormat(value int64) int64 {
    if value < 0 {
        return -value
    }

    return value
}
