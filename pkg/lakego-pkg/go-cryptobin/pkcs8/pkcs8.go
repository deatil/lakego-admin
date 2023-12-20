package pkcs8

import (
    "io"
    "errors"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs1"
    "github.com/deatil/go-cryptobin/pkcs/pbes1"
    "github.com/deatil/go-cryptobin/pkcs/pbes2"
    cryptobin_pbes1 "github.com/deatil/go-cryptobin/pkcs8/pbes1"
    cryptobin_pbes2 "github.com/deatil/go-cryptobin/pkcs8/pbes2"
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

    // PBES1
    MD2AndDES     = pbes1.MD2AndDES
    MD2AndRC2_64  = pbes1.MD2AndRC2_64
    MD5AndDES     = pbes1.MD5AndDES
    MD5AndRC2_64  = pbes1.MD5AndRC2_64
    SHA1AndDES    = pbes1.SHA1AndDES
    SHA1AndRC2_64 = pbes1.SHA1AndRC2_64

    // pkcs8 模式
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

    SM4ECB  = pbes2.SM4ECB
    SM4CBC  = pbes2.SM4CBC
    SM4OFB  = pbes2.SM4OFB
    SM4CFB  = pbes2.SM4CFB
    SM4CFB1 = pbes2.SM4CFB1
    SM4CFB8 = pbes2.SM4CFB8
    SM4GCM  = pbes2.SM4GCM
    SM4CCM  = pbes2.SM4CCM
)

type (
    // 配置
    Opts       = cryptobin_pbes2.Opts
    PBKDF2Opts = cryptobin_pbes2.PBKDF2Opts
    ScryptOpts = cryptobin_pbes2.ScryptOpts
)

var (
    // 获取 Cipher 类型
    GetCipherFromName = cryptobin_pbes2.GetCipherFromName
    // 获取 hash 类型
    GetHashFromName   = cryptobin_pbes2.GetHashFromName
)

// 默认配置 PBKDF2
var DefaultPBKDF2Opts = cryptobin_pbes2.DefaultPBKDF2Opts

// 默认配置 Scrypt
var DefaultScryptOpts = cryptobin_pbes2.DefaultScryptOpts

// 默认配置
var DefaultOpts = cryptobin_pbes2.DefaultOpts

// 解析设置
// opt, err := ParseOpts("AES256CBC", "SHA256")
// block, err := EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", data, password, opt)
func ParseOpts(opts ...any) (any, error) {
    var opt any
    var err error

    if len(opts) > 0 {
        if alg, ok := opts[0].(string); ok {
            if cryptobin_pbes1.CheckCipherFromName(alg) {
                opt = cryptobin_pbes1.GetCipherFromName(alg)
            }
        }
    }

    if opt == nil {
        opt, err = cryptobin_pbes2.ParseOpts(opts...)
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
        case cryptobin_pbes2.Cipher:
            if _, err := cryptobin_pbes2.GetCipher(c.OID().String()); err == nil {
                opts := DefaultOpts
                opts.Cipher = c

                return cryptobin_pbes2.EncryptPKCS8PrivateKey(rand, blockType, data, password, opts)
            }

            return cryptobin_pbes1.EncryptPKCS8PrivateKey(rand, blockType, data, password, c)

        case cryptobin_pbes2.Opts:
            if _, err := cryptobin_pbes1.GetCipher(c.Cipher.OID().String()); err == nil {
                return cryptobin_pbes1.EncryptPKCS8PrivateKey(rand, blockType, data, password, c.Cipher)
            }

            return cryptobin_pbes2.EncryptPKCS8PrivateKey(rand, blockType, data, password, c)
    }

    return nil, errors.New("pkcs8: unsupported cipher")
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

        if blockDecrypted, err = cryptobin_pbes2.DecryptPKCS8PrivateKey(block.Bytes, password); err == nil {
            return blockDecrypted, nil
        }

        if blockDecrypted, err = cryptobin_pbes1.DecryptPKCS8PrivateKey(block.Bytes, password); err == nil {
            return blockDecrypted, nil
        }

        return nil, err
    }

    return nil, errors.New("pkcs8: unsupported encrypted PEM")
}
