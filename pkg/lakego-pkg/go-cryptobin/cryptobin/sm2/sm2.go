package sm2

import (
    "hash"

    "github.com/deatil/go-cryptobin/gm/sm2"
)

const (
    // 类型
    C1C3C2 = sm2.C1C3C2
    C1C2C3 = sm2.C1C2C3
)

// 默认 UID
var defaultUID = []byte{
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
}

type (
    // HashFunc
    HashFunc = func() hash.Hash
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
    mode sm2.Mode

    // [私钥/公钥]数据
    keyData []byte

    // 传入数据
    data []byte

    // 解析后的数据
    parsedData []byte

    // 签名验证类型
    signHash HashFunc

    // UID
    uid []byte

    // 验证结果
    verify bool

    // 错误
    Errors []error
}

// 构造函数
func NewSM2() SM2 {
    return SM2{
        mode:   C1C3C2,
        uid:    defaultUID,
        verify: false,
        Errors: make([]error, 0),
    }
}

// 构造函数
func New() SM2 {
    return NewSM2()
}

var defaultSM2 = NewSM2()
