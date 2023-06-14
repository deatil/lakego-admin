package sm2

import (
    "github.com/tjfoc/gmsm/sm2"
)

/**
 * 国密 SM2 加密
 *
 * @create 2022-4-16
 * @author deatil
 */
type SM2 struct {
    // 私钥
    privateKey *sm2.PrivateKey

    // 公钥
    publicKey *sm2.PublicKey

    // 加密模式
    mode int

    // [私钥/公钥]数据
    keyData []byte

    // 传入数据
    data []byte

    // 解析后的数据
    paredData []byte

    // 验证结果
    verify bool

    // 错误
    Errors []error
}

// 构造函数
func NewSM2() SM2 {
    return SM2{
        mode:   sm2.C1C3C2,
        verify: false,
        Errors: make([]error, 0),
    }
}

// 构造函数
func New() SM2 {
    return NewSM2()
}

var defaultSM2 = NewSM2()
