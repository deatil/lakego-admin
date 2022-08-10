package dh

import (
    "math/big"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/dhd/dh"
)

type (
    // Group 别名
    Group = dh.Group
)

// 私钥
func (this Dh) FromPrivateKey(key []byte) Dh {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        this.Error = err
        return this
    }

    this.privateKey = parsedKey.(*dh.PrivateKey)

    return this
}

// 私钥带密码
func (this Dh) FromPrivateKeyWithPassword(key []byte, password string) Dh {
    parsedKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        this.Error = err
        return this
    }

    this.privateKey = parsedKey.(*dh.PrivateKey)

    return this
}

// 公钥
func (this Dh) FromPublicKey(key []byte) Dh {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        this.Error = err
        return this
    }

    this.publicKey = parsedKey.(*dh.PublicKey)

    return this
}

// 根据密钥 x, y 生成
func (this Dh) FromKeyXYHexString(name string, xString string, yString string) Dh {
    param := GetGroupIDFromName(name)

    paramGroup, err := dh.GetMODPGroup(param)
    if err != nil {
        this.Error = err
        return this
    }

    x, _ := new(big.Int).SetString(xString[:], 16)
    y, _ := new(big.Int).SetString(yString[:], 16)

    parameters := dh.Parameters{
        P: paramGroup.P,
        G: paramGroup.G,
    }

    priv := &dh.PrivateKey{}
    priv.X = x
    priv.PublicKey.Y = y
    priv.PublicKey.Parameters = parameters

    this.privateKey = priv
    this.publicKey  = &priv.PublicKey

    return this
}

// 根据私钥 x 生成
func (this Dh) FromPrivateKeyXHexString(name string, xString string) Dh {
    param := GetGroupIDFromName(name)

    paramGroup, err := dh.GetMODPGroup(param)
    if err != nil {
        this.Error = err
        return this
    }

    return this.FromPrivateKeyXHexStringWithGroup(paramGroup, xString)
}

// 根据私钥 x 生成
func (this Dh) FromPrivateKeyXHexStringWithGroup(group *dh.Group, xString string) Dh {
    x, _ := new(big.Int).SetString(xString[:], 16)

    parameters := dh.Parameters{
        P: group.P,
        G: group.G,
    }

    priv := &dh.PrivateKey{}
    priv.X = x
    priv.PublicKey.Parameters = parameters

    public, _ := dh.GeneratePublicKey(priv)
    priv.PublicKey = *public

    this.privateKey = priv

    return this
}

// 根据公钥 y 生成
func (this Dh) FromPublicKeyYHexString(name string, yString string) Dh {
    param := GetGroupIDFromName(name)

    paramGroup, err := dh.GetMODPGroup(param)
    if err != nil {
        this.Error = err
        return this
    }

    return this.FromPublicKeyYHexStringWithGroup(paramGroup, yString)
}

// 根据公钥 y 生成
func (this Dh) FromPublicKeyYHexStringWithGroup(group *dh.Group, yString string) Dh {
    y, _ := new(big.Int).SetString(yString[:], 16)

    parameters := dh.Parameters{
        P: group.P,
        G: group.G,
    }

    public := &dh.PublicKey{}
    public.Y = y
    public.Parameters = parameters

    this.publicKey = public

    return this
}

// 生成密钥
func (this Dh) GenerateKey(name string) Dh {
    param := GetGroupIDFromName(name)

    this.privateKey, this.publicKey, this.Error = dh.GenerateKey(param, rand.Reader)

    return this
}

// 根据名称获取分组
func GetGroupIDFromName(name string) dh.GroupID {
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

    return param
}
