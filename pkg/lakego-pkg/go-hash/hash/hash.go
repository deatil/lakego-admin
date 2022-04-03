package hash

// 构造函数
func NewHash() Hash {
    return Hash{}
}

/**
 * hash
 *
 * @create 2022-3-27
 * @author deatil
 */
type Hash struct {
    // 数据
    data [][]byte

    // 已 hash 数据
    hashedData string

    // 错误
    Error error
}

// 添加数据
func (this Hash) WithData(data ...[]byte) Hash {
    this.data = data

    return this
}

// 追加数据
func (this Hash) AppendData(data ...[]byte) Hash {
    this.data = append(this.data, data...)

    return this
}
