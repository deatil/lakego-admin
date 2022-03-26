package cryptobin

// 构造函数
func New() Crypto {
    return Crypto{}
}

/**
 * 对称加密
 *
 * @create 2022-3-19
 * @author deatil
 */
type Crypto struct {
    // 数据
    Data []byte

    // 密钥
    Key []byte

    // 向量
    Iv []byte

    // 加密类型
    Type string

    // 加密方式
    Mode string

    // 填充模式
    Padding string

    // 解析后的数据
    ParsedData []byte

    // 错误
    Error error
}
