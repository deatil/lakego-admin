package dh

import (
    "math/big"

    "github.com/deatil/go-cryptobin/dh/dh"
)

// 设置 PrivateKey
func (this DH) WithPrivateKey(data *dh.PrivateKey) DH {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this DH) WithPublicKey(data *dh.PublicKey) DH {
    this.publicKey = data

    return this
}

// 设置分组
func (this DH) WithGroup(data *dh.Group) DH {
    this.group = data

    return this
}

// 根据 Group 数据设置分组
func (this DH) SetGroup(name string) DH {
    var param dh.GroupID

    switch name {
        case "P1001":
            param = dh.P1001
        case "P1002":
            param = dh.P1002
        case "P1536":
            param = dh.P1536
        case "P2048":
            param = dh.P2048
        case "P3072":
            param = dh.P3072
        case "P4096":
            param = dh.P4096
        case "P6144":
            param = dh.P6144
        case "P8192":
            param = dh.P8192
        default:
            param = dh.P2048
    }

    paramGroup, err := dh.GetMODGroup(param)
    if err != nil {
        return this.AppendError(err)
    }

    this.group = paramGroup

    return this
}

// 根据 Group P和G 数据设置分组
func (this DH) SetGroupPG(p string, g int64) DH {
    pInt, _ := new(big.Int).SetString(p, 16)

    this.group = &dh.Group{
        P: pInt,
        G: big.NewInt(g),
    }

    return this
}

// 随机数
func (this DH) SetRandGroup(num int64) DH {
    hexLetters := []rune("0123456789abcdef")

    // p 值
    p := RandomString(num, hexLetters)

    pInt, _ := new(big.Int).SetString(p, 16)

    this.group = &dh.Group{
        P: pInt,
        G: big.NewInt(2),
    }

    return this
}

// 设置 keyData
func (this DH) WithKeyData(data []byte) DH {
    this.keyData = data

    return this
}

// 设置 secretData
func (this DH) WithSecretData(data []byte) DH {
    this.secretData = data

    return this
}

// 设置错误
func (this DH) WithError(errs []error) DH {
    this.Errors = errs

    return this
}
