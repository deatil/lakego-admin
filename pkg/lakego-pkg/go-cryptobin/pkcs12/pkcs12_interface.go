package pkcs12

import (
    "crypto"
    "encoding/asn1"

    cryptobin_pkcs8 "github.com/deatil/go-cryptobin/pkcs8"
    cryptobin_pkcs8pbe "github.com/deatil/go-cryptobin/pkcs8pbe"
)

// 加密接口
type Cipher interface {
    // oid
    OID() asn1.ObjectIdentifier

    // 值大小
    KeySize() int

    // 加密, 返回: [加密后数据, 参数, error]
    Encrypt(key, plaintext []byte) ([]byte, []byte, error)

    // 解密
    Decrypt(key, params, ciphertext []byte) ([]byte, error)
}

// Key 接口
type Key interface {
    // 包装默认证书
    MarshalPrivateKey(privateKey crypto.PrivateKey) (pkData []byte, err error)

    // 包装 PKCS8 证书
    MarshalPKCS8PrivateKey(privateKey crypto.PrivateKey) (pkData []byte, err error)

    // 解析 PKCS8 证书
    ParsePKCS8PrivateKey(pkData []byte) (crypto.PrivateKey, error)
}

// 数据接口
type KDFParameters interface {
    // 验证
    Verify(message []byte, password []byte) (err error)
}

// KDF 设置接口
type KDFOpts interface {
    // 构造
    Compute(message []byte, password []byte) (data KDFParameters, err error)
}

var keys = make(map[string]func() Key)

// 添加Key
func AddKey(name string, key func() Key) {
    keys[name] = key
}

var ciphers = make(map[string]func() Cipher)

// 添加加密
func AddCipher(oid asn1.ObjectIdentifier, cipher func() Cipher) {
    ciphers[oid.String()] = cipher
}

// ===============

// KDF 设置接口
type PKCS8KDFOpts = cryptobin_pkcs8.KDFOpts

// 配置
type Opts struct {
    PKCS8Cipher  Cipher
    PKCS8KDFOpts PKCS8KDFOpts
    Cipher       Cipher
    KDFOpts      KDFOpts
}

func (this Opts) WithPKCS8Cipher(cipher Cipher) Opts {
    this.PKCS8Cipher = cipher

    return this
}

func (this Opts) WithPKCS8KDFOpts(opts PKCS8KDFOpts) Opts {
    this.PKCS8KDFOpts = opts

    return this
}

func (this Opts) WithCipher(cipher Cipher) Opts {
    this.Cipher = cipher

    return this
}

func (this Opts) WithKDFOpts(opts KDFOpts) Opts {
    this.KDFOpts = opts

    return this
}

// 默认配置
var DefaultOpts = Opts{
    PKCS8Cipher: cryptobin_pkcs8pbe.PEMCipherSHA1And3DES,
    Cipher: CipherSHA1AndRC2_40,
    KDFOpts: MacOpts{
        SaltSize: 8,
        IterationCount: 1,
        HMACHash: SHA1,
    },
}

// ===============

type (
    // PBKDF2 配置
    PKCS8PBKDF2Opts = cryptobin_pkcs8.PBKDF2Opts
    // Scrypt 配置
    PKCS8ScryptOpts = cryptobin_pkcs8.ScryptOpts
)

var (
    // 获取 Cipher 类型
    GetPKCS8CipherFromName = cryptobin_pkcs8.GetCipherFromName
    // 获取 hash 类型
    GetPKCS8HashFromName   = cryptobin_pkcs8.GetHashFromName

    // 获取 Cipher 类型
    GetPKCS8PbeCipherFromName = cryptobin_pkcs8pbe.GetCipherFromName
    // 检测 Cipher 类型
    CheckPKCS8PbeCipherFromName = cryptobin_pkcs8pbe.CheckCipherFromName
)

