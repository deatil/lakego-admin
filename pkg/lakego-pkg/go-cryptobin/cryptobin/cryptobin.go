package cryptobin

// 构造函数
func New() Cryptobin {
    return Cryptobin{
        multiple: "Aes",
        mode: "ECB",
        padding: "Pkcs7",
        config: make(map[string][]byte),
    }
}

/**
 * 对称加密
 *
 * @create 2022-3-19
 * @author deatil
 */
type Cryptobin struct {
    // 数据
    data []byte

    // 密钥
    key []byte

    // 向量
    iv []byte

    // 加密类型
    multiple string

    // 加密方式
    mode string

    // 填充模式
    padding string

    // 解析后的数据
    parsedData []byte

    // 额外配置
    config map[string][]byte

    // 错误
    Error error
}
