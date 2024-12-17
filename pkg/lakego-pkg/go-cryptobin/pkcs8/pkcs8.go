package pkcs8

import (
    "io"
    "errors"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs1"
    "github.com/deatil/go-cryptobin/pkcs8/pbes1"
    "github.com/deatil/go-cryptobin/pkcs8/pbes2"
)

// 加密方式
var (
    // pkcs12
    SHA1And3DES    = pbes1.SHA1And3DES
    SHA1And2DES    = pbes1.SHA1And2DES
    SHA1AndRC2_128 = pbes1.SHA1AndRC2_128
    SHA1AndRC2_40  = pbes1.SHA1AndRC2_40
    SHA1AndRC4_128 = pbes1.SHA1AndRC4_128
    SHA1AndRC4_40  = pbes1.SHA1AndRC4_40

    MD5AndCAST5   = pbes1.MD5AndCAST5
    SHAAndTwofish = pbes1.SHAAndTwofish

    // pkcs8 - PBES1
    MD2AndDES     = pbes1.MD2AndDES
    MD2AndRC2_64  = pbes1.MD2AndRC2_64
    MD5AndDES     = pbes1.MD5AndDES
    MD5AndRC2_64  = pbes1.MD5AndRC2_64
    SHA1AndDES    = pbes1.SHA1AndDES
    SHA1AndRC2_64 = pbes1.SHA1AndRC2_64

    // pkcs8 - PBES2
    DESCBC     = pbes2.DESCBC
    DESEDE3CBC = pbes2.DESEDE3CBC

    RC2CBC     = pbes2.RC2CBC
    RC2_40CBC  = pbes2.RC2_40CBC
    RC2_64CBC  = pbes2.RC2_64CBC
    RC2_128CBC = pbes2.RC2_128CBC

    RC5CBC     = pbes2.RC5CBC
    RC5_128CBC = pbes2.RC5_128CBC
    RC5_192CBC = pbes2.RC5_192CBC
    RC5_256CBC = pbes2.RC5_256CBC

    AES128ECB = pbes2.AES128ECB
    AES128CBC = pbes2.AES128CBC
    AES128OFB = pbes2.AES128OFB
    AES128CFB = pbes2.AES128CFB
    AES128GCM = pbes2.AES128GCM
    AES128CCM = pbes2.AES128CCM

    AES192ECB = pbes2.AES192ECB
    AES192CBC = pbes2.AES192CBC
    AES192OFB = pbes2.AES192OFB
    AES192CFB = pbes2.AES192CFB
    AES192GCM = pbes2.AES192GCM
    AES192CCM = pbes2.AES192CCM

    AES256ECB = pbes2.AES256ECB
    AES256CBC = pbes2.AES256CBC
    AES256OFB = pbes2.AES256OFB
    AES256CFB = pbes2.AES256CFB
    AES256GCM = pbes2.AES256GCM
    AES256CCM = pbes2.AES256CCM

    SM4Cipher = pbes2.SM4Cipher
    SM4ECB    = pbes2.SM4ECB
    SM4CBC    = pbes2.SM4CBC
    SM4OFB    = pbes2.SM4OFB
    SM4CFB    = pbes2.SM4CFB
    SM4CFB1   = pbes2.SM4CFB1
    SM4CFB8   = pbes2.SM4CFB8
    SM4GCM    = pbes2.SM4GCM
    SM4CCM    = pbes2.SM4CCM

    GostCipher = pbes2.GostCipher

    // aria
    ARIA128ECB = pbes2.ARIA128ECB
    ARIA128CBC = pbes2.ARIA128CBC
    ARIA128CFB = pbes2.ARIA128CFB
    ARIA128OFB = pbes2.ARIA128OFB
    ARIA128CTR = pbes2.ARIA128CTR
    ARIA128GCM = pbes2.ARIA128GCM
    ARIA128CCM = pbes2.ARIA128CCM

    ARIA192ECB = pbes2.ARIA192ECB
    ARIA192CBC = pbes2.ARIA192CBC
    ARIA192CFB = pbes2.ARIA192CFB
    ARIA192OFB = pbes2.ARIA192OFB
    ARIA192CTR = pbes2.ARIA192CTR
    ARIA192GCM = pbes2.ARIA192GCM
    ARIA192CCM = pbes2.ARIA192CCM

    ARIA256ECB = pbes2.ARIA256ECB
    ARIA256CBC = pbes2.ARIA256CBC
    ARIA256CFB = pbes2.ARIA256CFB
    ARIA256OFB = pbes2.ARIA256OFB
    ARIA256CTR = pbes2.ARIA256CTR
    ARIA256GCM = pbes2.ARIA256GCM
    ARIA256CCM = pbes2.ARIA256CCM

    Misty1CBC = pbes2.Misty1CBC

    // Serpent
    Serpent128ECB = pbes2.Serpent128ECB
    Serpent128CBC = pbes2.Serpent128CBC
    Serpent128OFB = pbes2.Serpent128OFB
    Serpent128CFB = pbes2.Serpent128CFB

    Serpent192ECB = pbes2.Serpent192ECB
    Serpent192CBC = pbes2.Serpent192CBC
    Serpent192OFB = pbes2.Serpent192OFB
    Serpent192CFB = pbes2.Serpent192CFB

    Serpent256ECB = pbes2.Serpent256ECB
    Serpent256CBC = pbes2.Serpent256CBC
    Serpent256OFB = pbes2.Serpent256OFB
    Serpent256CFB = pbes2.Serpent256CFB

    // seed
    SeedECB = pbes2.SeedECB
    SeedCBC = pbes2.SeedCBC
    SeedOFB = pbes2.SeedOFB
    SeedCFB = pbes2.SeedCFB

    Seed256ECB = pbes2.Seed256ECB
    Seed256CBC = pbes2.Seed256CBC
    Seed256OFB = pbes2.Seed256OFB
    Seed256CFB = pbes2.Seed256CFB
)

type (
    // 配置
    Opts         = pbes2.Opts
    PBKDF2Opts   = pbes2.PBKDF2Opts
    SMPBKDF2Opts = pbes2.SMPBKDF2Opts
    ScryptOpts   = pbes2.ScryptOpts
)

var (
    // 获取 Cipher 类型
    GetCipherFromName = pbes2.GetCipherFromName
    // 获取 hash 类型
    GetHashFromName   = pbes2.GetHashFromName
)

var (
    // 默认 Hash
    DefaultHash   = pbes2.DefaultHash
    DefaultSMHash = pbes2.DefaultSMHash
)

var (
    // 默认配置 PBKDF2
    DefaultPBKDF2Opts = pbes2.DefaultPBKDF2Opts

    // 默认配置 GmSM PBKDF2
    DefaultSMPBKDF2Opts = pbes2.DefaultSMPBKDF2Opts

    // 默认配置 Scrypt
    DefaultScryptOpts = pbes2.DefaultScryptOpts

    // 默认配置
    DefaultOpts = pbes2.DefaultOpts

    // 默认 GmSM 配置
    DefaultSMOpts = pbes2.DefaultSMOpts
)

// 解析设置
// opt, err := ParseOpts("AES256CBC", "SHA256")
// block, err := EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", data, password, opt)
func ParseOpts(opts ...any) (any, error) {
    var opt any
    var err error

    if len(opts) > 0 {
        if alg, ok := opts[0].(string); ok {
            if pbes1.CheckCipherFromName(alg) {
                opt = pbes1.GetCipherFromName(alg)
            }
        }
    }

    if opt == nil {
        opt, err = pbes2.ParseOpts(opts...)
        if err != nil {
            return nil, err
        }
    }

    return opt, nil
}

// 加密
// block, err := EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", data, password, DESCBC)
// block, err := EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", data, password, DefaultOpts)
func EncryptPEMBlock(
    rand      io.Reader,
    blockType string,
    data      []byte,
    password  []byte,
    cipher    any,
) (*pem.Block, error) {
    switch c := cipher.(type) {
        case pbes2.Cipher:
            if _, err := pbes2.GetCipher(c.OID().String()); err == nil {
                opts := DefaultOpts
                opts.Cipher = c

                return pbes2.EncryptPKCS8PrivateKey(rand, blockType, data, password, opts)
            }

            return pbes1.EncryptPKCS8PrivateKey(rand, blockType, data, password, c)

        case pbes2.Opts:
            if _, err := pbes1.GetCipher(c.Cipher.OID().String()); err == nil {
                return pbes1.EncryptPKCS8PrivateKey(rand, blockType, data, password, c.Cipher)
            }

            return pbes2.EncryptPKCS8PrivateKey(rand, blockType, data, password, c)
    }

    return nil, errors.New("go-cryptobin/pkcs8: unsupported cipher")
}

// 解密
// de, err := DecryptPEMBlock(block, password)
func DecryptPEMBlock(block *pem.Block, password []byte) ([]byte, error) {
    if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
        return pkcs1.DecryptPEMBlock(block, password)
    }

    // PKCS#8 header defined in RFC7468 section 11
    if block.Type == "ENCRYPTED PRIVATE KEY" {
        var blockDecrypted []byte
        var err error

        if blockDecrypted, err = pbes2.DecryptPKCS8PrivateKey(block.Bytes, password); err == nil {
            return blockDecrypted, nil
        }

        if blockDecrypted, err = pbes1.DecryptPKCS8PrivateKey(block.Bytes, password); err == nil {
            return blockDecrypted, nil
        }

        return nil, err
    }

    return nil, errors.New("go-cryptobin/pkcs8: unsupported encrypted PEM")
}
