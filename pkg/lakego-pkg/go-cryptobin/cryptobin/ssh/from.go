package ecgdsa

import (
    "io"
    "crypto/rand"
    "crypto/rsa"
    "crypto/dsa"
    "crypto/ecdsa"
    "crypto/ed25519"

    "github.com/deatil/go-cryptobin/gm/sm2"
    "github.com/deatil/go-cryptobin/tool/encoding"
)

// 生成密钥
func (this SSH) GenerateKeyWithSeed(reader io.Reader) SSH {
    switch this.options.PublicKeyType {
        case KeyTypeRSA:
            privateKey, err := rsa.GenerateKey(reader, this.options.Bits)
            if err != nil {
                return this.AppendError(err)
            }

            this.privateKey = privateKey
            this.publicKey  = &privateKey.PublicKey
        case KeyTypeDSA:
            privateKey := &dsa.PrivateKey{}
            dsa.GenerateParameters(&privateKey.Parameters, reader, this.options.ParameterSizes)
            dsa.GenerateKey(privateKey, reader)

            this.privateKey = privateKey
            this.publicKey  = &privateKey.PublicKey
        case KeyTypeECDSA:
            privateKey, err := ecdsa.GenerateKey(this.options.Curve, reader)
            if err != nil {
                return this.AppendError(err)
            }

            this.privateKey = privateKey
            this.publicKey = &privateKey.PublicKey
        case KeyTypeEdDSA:
            publicKey, privateKey, err := ed25519.GenerateKey(reader)
            if err != nil {
                return this.AppendError(err)
            }

            this.privateKey = privateKey
            this.publicKey  = publicKey
        case KeyTypeSM2:
            privateKey, err := sm2.GenerateKey(reader)
            if err != nil {
                return this.AppendError(err)
            }

            this.privateKey = privateKey
            this.publicKey  = &privateKey.PublicKey
    }

    return this
}

// 使用自定义数据生成密钥对
func GenerateKeyWithSeed(reader io.Reader, options Options) SSH {
    return defaultSSH.
        WithOptions(options).
        GenerateKeyWithSeed(reader)
}

// 生成密钥
func (this SSH) GenerateKey() SSH {
    return this.GenerateKeyWithSeed(rand.Reader)
}

// 生成密钥对
func GenerateKey(options Options) SSH {
    return defaultSSH.
        WithOptions(options).
        GenerateKey()
}

// ==========

// 私钥
func (this SSH) FromPrivateKey(key []byte) SSH {
    return this.FromOpensshPrivateKey(key)
}

// 私钥
func FromPrivateKey(key []byte) SSH {
    return defaultSSH.FromPrivateKey(key)
}

// 私钥带密码
func (this SSH) FromPrivateKeyWithPassword(key []byte, password []byte) SSH {
    return this.FromOpensshPrivateKeyWithPassword(key, password)
}

// 私钥带密码
func FromPrivateKeyWithPassword(key []byte, password []byte) SSH {
    return defaultSSH.FromPrivateKeyWithPassword(key, password)
}

// 公钥
func (this SSH) FromPublicKey(key []byte) SSH {
    return defaultSSH.FromOpensshPublicKey(key)
}

// 公钥
func FromPublicKey(key []byte) SSH {
    return defaultSSH.FromPublicKey(key)
}

// ==========

// 私钥
func (this SSH) FromOpensshPrivateKey(key []byte) SSH {
    privateKey, comment, err := this.ParseOpensshPrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.options.Comment = comment

    return this
}

// 私钥
func FromOpensshPrivateKey(key []byte) SSH {
    return defaultSSH.FromOpensshPrivateKey(key)
}

// 私钥带密码
func (this SSH) FromOpensshPrivateKeyWithPassword(key []byte, password []byte) SSH {
    privateKey, comment, err := this.ParseOpensshPrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.options.Comment = comment

    return this
}

// 私钥
func FromOpensshPrivateKeyWithPassword(key []byte, password []byte) SSH {
    return defaultSSH.FromOpensshPrivateKeyWithPassword(key, password)
}

// 公钥
func (this SSH) FromOpensshPublicKey(key []byte) SSH {
    publicKey, comment, err := this.ParseOpensshPublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey
    this.options.Comment = comment

    return this
}

// 公钥
func FromOpensshPublicKey(key []byte) SSH {
    return defaultSSH.FromOpensshPublicKey(key)
}

// ==========

// 字节
func (this SSH) FromBytes(data []byte) SSH {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) SSH {
    return defaultSSH.FromBytes(data)
}

// 字符
func (this SSH) FromString(data string) SSH {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) SSH {
    return defaultSSH.FromString(data)
}

// Base64
func (this SSH) FromBase64String(data string) SSH {
    newData, err := encoding.Base64Decode(data)

    this.data = newData

    return this.AppendError(err)
}

// Base64
func FromBase64String(data string) SSH {
    return defaultSSH.FromBase64String(data)
}

// Hex
func (this SSH) FromHexString(data string) SSH {
    newData, err := encoding.HexDecode(data)

    this.data = newData

    return this.AppendError(err)
}

// Hex
func FromHexString(data string) SSH {
    return defaultSSH.FromHexString(data)
}
