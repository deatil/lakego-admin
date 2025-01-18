package ssh

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

// Generate Key with Reader
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

// Generate Key with Reader
func GenerateKeyWithSeed(reader io.Reader, options ...Options) SSH {
    if len(options) > 0 {
        return defaultSSH.
            WithOptions(options[0]).
            GenerateKeyWithSeed(reader)
    }

    return defaultSSH.GenerateKeyWithSeed(reader)
}

// Generate Key
func (this SSH) GenerateKey() SSH {
    return this.GenerateKeyWithSeed(rand.Reader)
}

// Generate Key
func GenerateKey(options ...Options) SSH {
    if len(options) > 0 {
        return defaultSSH.
            WithOptions(options[0]).
            GenerateKey()
    }

    return defaultSSH.GenerateKey()
}

// ==========

// From PrivateKey
func (this SSH) FromPrivateKey(key []byte) SSH {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// From PrivateKey
func FromPrivateKey(key []byte) SSH {
    return defaultSSH.FromPrivateKey(key)
}

// From PrivateKey With Password
func (this SSH) FromPrivateKeyWithPassword(key []byte, password []byte) SSH {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// From PrivateKey With Password
func FromPrivateKeyWithPassword(key []byte, password []byte) SSH {
    return defaultSSH.FromPrivateKeyWithPassword(key, password)
}

// From PublicKey
func (this SSH) FromPublicKey(key []byte) SSH {
    publicKey, err := this.ParsePKCS8PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// From PublicKey
func FromPublicKey(key []byte) SSH {
    return defaultSSH.FromPublicKey(key)
}

// ==========

// from OpenSSH PrivateKey
func (this SSH) FromOpenSSHPrivateKey(key []byte) SSH {
    privateKey, comment, cipherName, err := this.ParseOpenSSHPrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.options.Comment = comment
    this.options.CipherName = cipherName

    return this
}

// from OpenSSH PrivateKey
func FromOpenSSHPrivateKey(key []byte) SSH {
    return defaultSSH.FromOpenSSHPrivateKey(key)
}

// from OpenSSH PrivateKey with password
func (this SSH) FromOpenSSHPrivateKeyWithPassword(key []byte, password []byte) SSH {
    privateKey, comment, cipherName, err := this.ParseOpenSSHPrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.options.Comment = comment
    this.options.CipherName = cipherName

    return this
}

// from OpenSSH PrivateKey with password
func FromOpenSSHPrivateKeyWithPassword(key []byte, password []byte) SSH {
    return defaultSSH.FromOpenSSHPrivateKeyWithPassword(key, password)
}

// from OpenSSH PublicKey
func (this SSH) FromOpenSSHPublicKey(key []byte) SSH {
    publicKey, comment, err := this.ParseOpenSSHPublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey
    this.options.Comment = comment

    return this
}

// from OpenSSH PublicKey
func FromOpenSSHPublicKey(key []byte) SSH {
    return defaultSSH.FromOpenSSHPublicKey(key)
}

// ==========

// from bytes
func (this SSH) FromBytes(data []byte) SSH {
    this.data = data

    return this
}

// from bytes
func FromBytes(data []byte) SSH {
    return defaultSSH.FromBytes(data)
}

// from string
func (this SSH) FromString(data string) SSH {
    this.data = []byte(data)

    return this
}

// from string
func FromString(data string) SSH {
    return defaultSSH.FromString(data)
}

// from Base64 string
func (this SSH) FromBase64String(data string) SSH {
    newData, err := encoding.Base64Decode(data)

    this.data = newData

    return this.AppendError(err)
}

// from Base64 string
func FromBase64String(data string) SSH {
    return defaultSSH.FromBase64String(data)
}

// from Hex string
func (this SSH) FromHexString(data string) SSH {
    newData, err := encoding.HexDecode(data)

    this.data = newData

    return this.AppendError(err)
}

// from Hex string
func FromHexString(data string) SSH {
    return defaultSSH.FromHexString(data)
}
