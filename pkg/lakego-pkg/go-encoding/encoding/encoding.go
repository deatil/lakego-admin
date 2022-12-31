package encoding

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

var defaultEncode Encoding

// 初始化
func init() {
    defaultEncode = NewEncoding()
}

// 构造函数
func NewEncoding() Encoding {
    return Encoding{}
}

// 构造函数
func New() Encoding {
    return NewEncoding()
}
