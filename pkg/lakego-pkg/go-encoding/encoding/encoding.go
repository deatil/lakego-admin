package encoding

// 构造函数
func New() Encoding {
    return Encoding{}
}

/**
 * 编码
 *
 * @create 2022-4-3
 * @author deatil
 */
type Encoding struct {
    // 数据
    data []byte

    // 错误
    Error error
}
