package ecgdsa

import (
    "crypto"
    "crypto/dsa"
    "crypto/elliptic"

    "golang.org/x/crypto/ssh"
)

// 设置 PrivateKey
func (this SSH) WithPrivateKey(key crypto.PrivateKey) SSH {
    this.privateKey = key

    return this
}

// 设置 PublicKey
func (this SSH) WithPublicKey(key crypto.PublicKey) SSH {
    this.publicKey = key

    return this
}

// 设置 openssh PublicKey
func (this SSH) SetOpensshPublicKey(key ssh.PublicKey) SSH {
    publicKey, err := ssh.NewPublicKey(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// 设置配置
func (this SSH) WithOptions(options Options) SSH {
    this.options = options

    return this
}

// public key type
func (this SSH) WithPublicKeyType(keyType PublicKeyType) SSH {
    this.options.PublicKeyType = keyType

    return this
}

// public key type
// 可选参数:
// [ RSA | DSA | ECDSA | EdDSA | SM2 ]
func (this SSH) SetPublicKeyType(keyType string) SSH {
    switch keyType {
        case "RSA":
            this.options.PublicKeyType = KeyTypeRSA
        case "DSA":
            this.options.PublicKeyType = KeyTypeDSA
        case "ECDSA":
            this.options.PublicKeyType = KeyTypeECDSA
        case "EdDSA":
            this.options.PublicKeyType = KeyTypeEdDSA
        case "SM2":
            this.options.PublicKeyType = KeyTypeSM2
    }

    return this
}

// 设置注释
func (this SSH) WithComment(comment string) SSH {
    this.options.Comment = comment

    return this
}

// 设置 DSA ParameterSizes
func (this SSH) WithParameterSizes(sizes dsa.ParameterSizes) SSH {
    this.options.ParameterSizes = sizes

    return this
}

// 设置 DSA ParameterSizes
// 可选参数:
// [ L1024N160 | L2048N224 | L2048N256 | L3072N256 ]
func (this SSH) SetParameterSizes(ln string) SSH {
    switch ln {
        case "L1024N160":
            this.options.ParameterSizes = dsa.L1024N160
        case "L2048N224":
            this.options.ParameterSizes = dsa.L2048N224
        case "L2048N256":
            this.options.ParameterSizes = dsa.L2048N256
        case "L3072N256":
            this.options.ParameterSizes = dsa.L3072N256
    }

    return this
}

// 设置曲线类型
func (this SSH) WithCurve(curve elliptic.Curve) SSH {
    this.options.Curve = curve

    return this
}

// 设置曲线类型
// 可选参数: [ P521 | P384 | P256 ]
func (this SSH) SetCurve(curve string) SSH {
    switch curve {
        case "P256":
            this.options.Curve = elliptic.P256()
        case "P384":
            this.options.Curve = elliptic.P384()
        case "P521":
            this.options.Curve = elliptic.P521()
    }

    return this
}

// RSA private key bit size
func (this SSH) WithBits(bits int) SSH {
    this.options.Bits = bits

    return this
}

// 设置 keyData
func (this SSH) WithKeyData(data []byte) SSH {
    this.keyData = data

    return this
}

// 设置 data
func (this SSH) WithData(data []byte) SSH {
    this.data = data

    return this
}

// 设置 parsedData
func (this SSH) WithParsedData(data []byte) SSH {
    this.parsedData = data

    return this
}

// 设置验证结果
func (this SSH) WithVerify(data bool) SSH {
    this.verify = data

    return this
}

// 设置错误
func (this SSH) WithErrors(errs []error) SSH {
    this.Errors = errs

    return this
}
