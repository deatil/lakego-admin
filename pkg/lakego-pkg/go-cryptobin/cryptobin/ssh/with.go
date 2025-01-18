package ssh

import (
    "errors"
    "crypto"
    "crypto/dsa"
    "crypto/elliptic"

    "golang.org/x/crypto/ssh"

    cryptobin_ssh "github.com/deatil/go-cryptobin/ssh"
)

// With PrivateKey
func (this SSH) WithPrivateKey(key crypto.PrivateKey) SSH {
    this.privateKey = key

    return this
}

// With PublicKey
func (this SSH) WithPublicKey(key crypto.PublicKey) SSH {
    this.publicKey = key

    return this
}

// With openssh PublicKey
func (this SSH) SetOpenSSHPublicKey(key ssh.PublicKey) SSH {
    publicKey, err := cryptobin_ssh.NewPublicKey(key)
    if err != nil {
        return this.AppendError(err)
    }

    pkey, ok := publicKey.(ssh.CryptoPublicKey)
    if !ok {
        err := errors.New("ssh PublicKey error.")
        return this.AppendError(err)
    }

    this.publicKey = pkey.CryptoPublicKey()

    return this
}

// With options
func (this SSH) WithOptions(options Options) SSH {
    this.options = options

    return this
}

// public key type
func (this SSH) WithPublicKeyType(keyType PublicKeyType) SSH {
    this.options.PublicKeyType = keyType

    return this
}

// set public key type
// params:
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

// set Generate public key type
// params:
// [ RSA | DSA | ECDSA | EdDSA | SM2 ]
func (this SSH) SetGenerateType(typ string) SSH {
    return this.SetPublicKeyType(typ)
}

// With CipherName
func (this SSH) WithCipherName(cipherName string) SSH {
    this.options.CipherName = cipherName

    return this
}

// Set Cipher
func (this SSH) SetCipher(cip cryptobin_ssh.Cipher) SSH {
    this.options.CipherName = cip.Name()

    return this
}

// With Comment
func (this SSH) WithComment(comment string) SSH {
    this.options.Comment = comment

    return this
}

// With DSA ParameterSizes
func (this SSH) WithParameterSizes(sizes dsa.ParameterSizes) SSH {
    this.options.ParameterSizes = sizes

    return this
}

// With DSA ParameterSizes
// params:
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

// With Curve type
func (this SSH) WithCurve(curve elliptic.Curve) SSH {
    this.options.Curve = curve

    return this
}

// set Curve type
// params: [ P521 | P384 | P256 ]
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

// With keyData
func (this SSH) WithKeyData(data []byte) SSH {
    this.keyData = data

    return this
}

// With data
func (this SSH) WithData(data []byte) SSH {
    this.data = data

    return this
}

// With parsedData
func (this SSH) WithParsedData(data []byte) SSH {
    this.parsedData = data

    return this
}

// With Verify
func (this SSH) WithVerify(data bool) SSH {
    this.verify = data

    return this
}

// With Errors
func (this SSH) WithErrors(errs []error) SSH {
    this.Errors = errs

    return this
}
