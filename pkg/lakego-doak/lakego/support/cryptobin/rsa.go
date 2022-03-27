package cryptobin

// 构造函数
func NewRsa() *Rsa {
    return &Rsa{
        hash: "SHA512",
    }
}

/**
 * Rsa 加密
 *
 * @create 2021-8-28
 * @author deatil
 */
type Rsa struct {
    // 签名验证类型
    hash string
}

// 设置 hash 类型
func (this Rsa) WithKey(data string) Rsa {
    this.hash = data

    return this
}
