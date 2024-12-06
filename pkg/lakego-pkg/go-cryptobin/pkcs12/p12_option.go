package pkcs12

import (
    "crypto"
    "crypto/x509"

    "github.com/deatil/go-cryptobin/pkcs8/pbes1"
    "github.com/deatil/go-cryptobin/pkcs8/pbes2"
    "github.com/deatil/go-cryptobin/pkcs12/enveloped"
)

type (
    // PBKDF2 配置
    PBKDF2Opts = pbes2.PBKDF2Opts
    // Scrypt 配置
    ScryptOpts = pbes2.ScryptOpts

    // KDF 设置接口
    KeyKDFOpts  = pbes2.KDFOpts
    CertKDFOpts = pbes2.KDFOpts
)

var (
    // 获取 Cipher 类型
    GetPbes1CipherFromName   = pbes1.GetCipherFromName
    // 检测 Cipher 类型
    CheckPbes1CipherFromName = pbes1.CheckCipherFromName

    // 获取 Cipher 类型
    GetPbes2CipherFromName = pbes2.GetCipherFromName
    // 获取 hash 类型
    GetPbes2HashFromName   = pbes2.GetHashFromName
)

// Enveloped 加密配置
type EnvelopedOpts struct {
    // 加密方式
    Cipher     enveloped.Cipher
    KeyEncrypt enveloped.KeyEncrypt
    // 加密参数
    Recipients []*x509.Certificate
    // 解密参数
    Cert       *x509.Certificate
    PrivateKey crypto.PrivateKey
}

// 配置
type Opts struct {
    KeyCipher   Cipher
    KeyKDFOpts  KeyKDFOpts
    CertCipher  Cipher
    CertKDFOpts CertKDFOpts
    MacKDFOpts  MacKDFOpts
}

func (this Opts) WithKeyCipher(cipher Cipher) Opts {
    this.KeyCipher = cipher

    return this
}

func (this Opts) WithKeyKDFOpts(opts KeyKDFOpts) Opts {
    this.KeyKDFOpts = opts

    return this
}

func (this Opts) WithCertCipher(cipher Cipher) Opts {
    this.CertCipher = cipher

    return this
}

func (this Opts) WithCertKDFOpts(opts CertKDFOpts) Opts {
    this.CertKDFOpts = opts

    return this
}

func (this Opts) WithMacKDFOpts(opts MacKDFOpts) Opts {
    this.MacKDFOpts = opts

    return this
}

// LegacyRC2
var LegacyRC2Opts = Opts{
    KeyCipher:  pbes1.SHA1And3DES,
    CertCipher: CipherSHA1AndRC2_40,
    MacKDFOpts: MacOpts{
        SaltSize:       8,
        IterationCount: 1,
        HMACHash:       SHA1,
    },
}

// LegacyDES
var LegacyDESOpts = Opts{
    KeyCipher:  pbes1.SHA1And3DES,
    CertCipher: CipherSHA1And3DES,
    MacKDFOpts: MacOpts{
        SaltSize:       8,
        IterationCount: 1,
        HMACHash:       SHA1,
    },
}

// Passwordless
var PasswordlessOpts = Opts{
    KeyCipher:  nil,
    CertCipher: nil,
    MacKDFOpts: nil,
}

// Modern2023
var Modern2023Opts = Opts{
    KeyCipher:  pbes2.AES256CBC,
    KeyKDFOpts: PBKDF2Opts{
        SaltSize:       16,
        IterationCount: 2048,
    },
    CertCipher:  pbes2.AES256CBC,
    CertKDFOpts: PBKDF2Opts{
        SaltSize:       16,
        IterationCount: 2048,
    },
    MacKDFOpts: MacOpts{
        SaltSize:       16,
        IterationCount: 2048,
        HMACHash:       SHA256,
    },
}

// LegacyGost
var LegacyGostOpts = Opts{
    KeyCipher:  pbes2.GostCipher,
    KeyKDFOpts: PBKDF2Opts{
        SaltSize:       32,
        IterationCount: 2000,
        HMACHash:       GetPbes2HashFromName("GOST34112012512"),
    },
    CertCipher:  pbes2.GostCipher,
    CertKDFOpts: PBKDF2Opts{
        SaltSize:       32,
        IterationCount: 2000,
        HMACHash:       GetPbes2HashFromName("GOST34112012512"),
    },
    MacKDFOpts: MacOpts{
        SaltSize:       32,
        IterationCount: 2000,
        HMACHash:       GOST34112012512,
    },
}

// LegacyGmsm
var LegacyGmsmOpts = Opts{
    KeyCipher:  pbes2.SM4CBC,
    KeyKDFOpts: PBKDF2Opts{
        SaltSize:       16,
        IterationCount: 1000,
        HMACHash:       GetPbes2HashFromName("SM3"),
    },
    CertCipher:  pbes2.SM4CBC,
    CertKDFOpts: PBKDF2Opts{
        SaltSize:       16,
        IterationCount: 1000,
        HMACHash:       GetPbes2HashFromName("SM3"),
    },
    MacKDFOpts: MacOpts{
        SaltSize:       16,
        IterationCount: 1000,
        HMACHash:       SM3,
    },
}

// LegacyPBMAC1
var LegacyPBMAC1Opts = Opts{
    KeyCipher:  pbes2.AES256CBC,
    KeyKDFOpts: PBKDF2Opts{
        SaltSize:       8,
        IterationCount: 2048,
    },
    CertCipher:  pbes2.AES256CBC,
    CertKDFOpts: PBKDF2Opts{
        SaltSize:       8,
        IterationCount: 2048,
    },
    MacKDFOpts: PBMAC1Opts{
        HasKeyLength:   true,
        SaltSize:       8,
        IterationCount: 2048,
        KDFHash:        PBMAC1SHA256,
        HMACHash:       PBMAC1SHA256,
    },
}

// LegacyOpts
var LegacyOpts = LegacyDESOpts

// ModernOpts
var ModernOpts = Modern2023Opts

// Shangmi2024Opts
var Shangmi2024Opts = LegacyGmsmOpts

// Default Opts
var DefaultOpts = LegacyRC2Opts
