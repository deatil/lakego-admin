package tool

import (
    "crypto"

    youmarkPKCS8 "github.com/youmark/pkcs8"
)

type (
    // 设置选项
    YoumarkPKCS8Opts = youmarkPKCS8.Opts
)

var (
    // 创建私钥默认可用选项
    // HMACHash 目前支持 SHA256 和 SHA1
    Youmark_PKCS8_AES128CBC_SHA256 = youmarkPKCS8.Opts{
        Cipher: youmarkPKCS8.AES128CBC,
        KDFOpts: youmarkPKCS8.PBKDF2Opts{
            SaltSize: 8,
            IterationCount: 2048,
            HMACHash: crypto.SHA256,
        },
    }

    Youmark_PKCS8_AES192CBC_SHA256 = youmarkPKCS8.Opts{
        Cipher: youmarkPKCS8.AES192CBC,
        KDFOpts: youmarkPKCS8.PBKDF2Opts{
            SaltSize: 8,
            IterationCount: 1000,
            HMACHash: crypto.SHA256,
        },
    }

    Youmark_PKCS8_AES256CBC_SHA256 = youmarkPKCS8.Opts{
        Cipher: youmarkPKCS8.AES256CBC,
        KDFOpts: youmarkPKCS8.PBKDF2Opts{
            SaltSize: 16,
            IterationCount: 2000,
            HMACHash: crypto.SHA256,
        },
    }

    Youmark_PKCS8_AES128GCM_SHA256 = youmarkPKCS8.Opts{
        Cipher: youmarkPKCS8.AES128GCM,
        KDFOpts: youmarkPKCS8.PBKDF2Opts{
            SaltSize: 8,
            IterationCount: 2048,
            HMACHash: crypto.SHA256,
        },
    }

    Youmark_PKCS8_AES192GCM_SHA256 = youmarkPKCS8.Opts{
        Cipher: youmarkPKCS8.AES192GCM,
        KDFOpts: youmarkPKCS8.PBKDF2Opts{
            SaltSize: 8,
            IterationCount: 10000,
            HMACHash: crypto.SHA256,
        },
    }

    Youmark_PKCS8_AES256GCM_SHA256 = youmarkPKCS8.Opts{
        Cipher: youmarkPKCS8.AES256GCM,
        KDFOpts: youmarkPKCS8.PBKDF2Opts{
            SaltSize: 16,
            IterationCount: 16,
            HMACHash: crypto.SHA256,
        },
    }

    Youmark_PKCS8_TripleDESCBC_SHA1 = youmarkPKCS8.Opts{
        Cipher: youmarkPKCS8.TripleDESCBC,
        KDFOpts: youmarkPKCS8.PBKDF2Opts{
            SaltSize: 16,
            IterationCount: 16,
            HMACHash: crypto.SHA1,
        },
    }

    Youmark_PKCS8_AES256CBC_Scrypt = youmarkPKCS8.Opts{
        Cipher: youmarkPKCS8.AES256CBC,
        KDFOpts: youmarkPKCS8.ScryptOpts{
            CostParameter:            1 << 2,
            BlockSize:                8,
            ParallelizationParameter: 1,
            SaltSize:                 16,
        },
    }
)

// 设置私钥带密码
func YoumarkPKCS8ParsePrivateKey(der []byte, password []byte) (any, youmarkPKCS8.KDFParameters, error) {
    return youmarkPKCS8.ParsePrivateKey(der, password)
}

// 创建私钥带密码
func YoumarkPKCS8MarshalPrivateKey(priv any, password []byte, opts *youmarkPKCS8.Opts) ([]byte, error) {
    return youmarkPKCS8.MarshalPrivateKey(priv, password, opts)
}
