package cryptobin

import (
    "errors"
    "crypto"
    "crypto/rsa"
    "encoding/pem"

    youmarkPkcs8 "github.com/youmark/pkcs8"
)

var (
    // 创建私钥默认可用选项
    // HMACHash 目前支持 SHA256 和 SHA1
    Youmark_AES128CBC_SHA256 = youmarkPkcs8.Opts{
        Cipher: youmarkPkcs8.AES128CBC,
        KDFOpts: youmarkPkcs8.PBKDF2Opts{
            SaltSize: 8,
            IterationCount: 2048,
            HMACHash: crypto.SHA256,
        },
    }

    Youmark_AES192CBC_SHA256 = youmarkPkcs8.Opts{
        Cipher: youmarkPkcs8.AES192CBC,
        KDFOpts: youmarkPkcs8.PBKDF2Opts{
            SaltSize: 8,
            IterationCount: 1000,
            HMACHash: crypto.SHA256,
        },
    }

    Youmark_AES256CBC_SHA256 = youmarkPkcs8.Opts{
        Cipher: youmarkPkcs8.AES256CBC,
        KDFOpts: youmarkPkcs8.PBKDF2Opts{
            SaltSize: 16,
            IterationCount: 2000,
            HMACHash: crypto.SHA256,
        },
    }

    Youmark_AES128GCM_SHA256 = youmarkPkcs8.Opts{
        Cipher: youmarkPkcs8.AES128GCM,
        KDFOpts: youmarkPkcs8.PBKDF2Opts{
            SaltSize: 8,
            IterationCount: 2048,
            HMACHash: crypto.SHA256,
        },
    }

    Youmark_AES192GCM_SHA256 = youmarkPkcs8.Opts{
        Cipher: youmarkPkcs8.AES192GCM,
        KDFOpts: youmarkPkcs8.PBKDF2Opts{
            SaltSize: 8,
            IterationCount: 10000,
            HMACHash: crypto.SHA256,
        },
    }

    Youmark_AES256GCM_SHA256 = youmarkPkcs8.Opts{
        Cipher: youmarkPkcs8.AES256GCM,
        KDFOpts: youmarkPkcs8.PBKDF2Opts{
            SaltSize: 16,
            IterationCount: 16,
            HMACHash: crypto.SHA256,
        },
    }

    Youmark_TripleDESCBC_SHA1 = youmarkPkcs8.Opts{
        Cipher: youmarkPkcs8.TripleDESCBC,
        KDFOpts: youmarkPkcs8.PBKDF2Opts{
            SaltSize: 16,
            IterationCount: 16,
            HMACHash: crypto.SHA1,
        },
    }

    Youmark_AES256CBC_Scrypt = youmarkPkcs8.Opts{
        Cipher: youmarkPkcs8.AES256CBC,
        KDFOpts: youmarkPkcs8.ScryptOpts{
            CostParameter:            1 << 2,
            BlockSize:                8,
            ParallelizationParameter: 1,
            SaltSize:                 16,
        },
    }
)

// 设置私钥带密码
func RsaFromYoumarkPKCS8WithPassword(key []byte, password string) Rsa {
    return NewRsa().FromYoumarkPKCS8WithPassword(key, password)
}

// 设置私钥带密码
func (this Rsa) FromYoumarkPKCS8WithPassword(key []byte, password string) Rsa {
    var err error

    // 解析 PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        this.Error = errors.New("invalid key: Key must be a PEM encoded PKCS8 key")

        return this
    }

    var parsedKey interface{}
    if parsedKey, _, err = youmarkPkcs8.ParsePrivateKey(block.Bytes, []byte(password)); err != nil {
        this.Error = err

        return this
    }

    var pkey *rsa.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
        this.Error = errors.New("key is not a valid RSA private key")

        return this
    }

    this.privateKey = pkey

    return this
}

// 创建私钥带密码
func (this Rsa) CreateYoumarkPKCS8WithPassword(password string, opt ...youmarkPkcs8.Opts) Rsa {
    var opts youmarkPkcs8.Opts

    if len(opt) > 0 {
        opts = opt[0]
    } else {
        opts = Youmark_AES256CBC_SHA256
    }

    der, err := youmarkPkcs8.MarshalPrivateKey(this.privateKey, []byte(password), &opts)
    if err != nil {
        this.Error = err

        return this
    }

    block := &pem.Block{
        Type: "ENCRYPTED PRIVATE KEY",
        Bytes: der,
    }

    this.keyData = pem.EncodeToMemory(block)

    return this
}
