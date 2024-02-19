package dh

import (
    cryptobin_dh "github.com/deatil/go-cryptobin/dh/dh"
)

type (
    // Group 别名
    Group = cryptobin_dh.Group
)

/**
 * dh
 *
 * @create 2022-8-7
 * @author deatil
 */
type DH struct {
    // 私钥
    privateKey *cryptobin_dh.PrivateKey

    // 公钥
    publicKey *cryptobin_dh.PublicKey

    // 分组
    group *cryptobin_dh.Group

    // [私钥/公钥]数据
    keyData []byte

    // 解析后的数据
    secretData []byte

    // 错误
    Errors []error
}

// 构造函数
func NewDH() DH {
    group, _ := cryptobin_dh.GetMODGroup(cryptobin_dh.P2048)

    return DH{
        group: group,
        Errors: make([]error, 0),
    }
}

// 构造函数
func New() DH {
    return NewDH()
}

var (
    // 默认
    defaultDH = NewDH()
)
