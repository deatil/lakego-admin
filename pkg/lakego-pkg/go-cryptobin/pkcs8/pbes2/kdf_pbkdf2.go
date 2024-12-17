package pbes2

import (
    "fmt"
    "hash"
    "errors"
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "crypto/x509/pkix"
    "encoding/asn1"

    "golang.org/x/crypto/pbkdf2"

    "github.com/deatil/go-cryptobin/hash/sm3"
    "github.com/deatil/go-cryptobin/hash/gost/gost34112012256"
    "github.com/deatil/go-cryptobin/hash/gost/gost34112012512"
)

// pkcs8 可使用的 hash 方式
type Hash uint

const (
    MD5 Hash = 1 + iota
    SHA1
    SHA224
    SHA256
    SHA384
    SHA512
    SHA512_224
    SHA512_256
    SM3
    GOST34112012256
    GOST34112012512
)

var (
    // 默认 hash
    DefaultHash = SHA1
)

var (
    // key derivation functions
    oidPKCS5       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5}
    oidPKCS5PBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}

    // hash 方式
    oidDigestAlgorithm    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2}
    oidHMACWithMD5        = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 6}
    oidHMACWithSHA1       = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
    oidHMACWithSHA224     = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
    oidHMACWithSHA256     = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
    oidHMACWithSHA384     = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
    oidHMACWithSHA512     = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
    oidHMACWithSHA512_224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 12}
    oidHMACWithSHA512_256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 13}
    oidHMACWithSM3        = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401, 2}

    oidHMACWithGOST34112012256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 4, 1}
    oidHMACWithGOST34112012512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 4, 2}
)

// 返回使用的 Hash 方式
func prfByOID(oid asn1.ObjectIdentifier) (func() hash.Hash, error) {
    switch {
        case oid.Equal(oidHMACWithMD5):
            return md5.New, nil
        case oid.Equal(oidHMACWithSHA1):
            return sha1.New, nil
        case oid.Equal(oidHMACWithSHA224):
            return sha256.New224, nil
        case oid.Equal(oidHMACWithSHA256):
            return sha256.New, nil
        case oid.Equal(oidHMACWithSHA384):
            return sha512.New384, nil
        case oid.Equal(oidHMACWithSHA512):
            return sha512.New, nil
        case oid.Equal(oidHMACWithSHA512_224):
            return sha512.New512_224, nil
        case oid.Equal(oidHMACWithSHA512_256):
            return sha512.New512_256, nil
        case oid.Equal(oidHMACWithSM3):
            return sm3.New, nil
        case oid.Equal(oidHMACWithGOST34112012256):
            return gost34112012256.New, nil
        case oid.Equal(oidHMACWithGOST34112012512):
            return gost34112012512.New, nil
    }

    return nil, fmt.Errorf("go-cryptobin/pkcs8: unsupported hash (OID: %s)", oid)
}

// 返回使用的 Hash 对应的 asn1
func oidByHash(h Hash) (asn1.ObjectIdentifier, error) {
    switch h {
        case MD5:
            return oidHMACWithMD5, nil
        case SHA1:
            return oidHMACWithSHA1, nil
        case SHA224:
            return oidHMACWithSHA224, nil
        case SHA256:
            return oidHMACWithSHA256, nil
        case SHA384:
            return oidHMACWithSHA384, nil
        case SHA512:
            return oidHMACWithSHA512, nil
        case SHA512_224:
            return oidHMACWithSHA512_224, nil
        case SHA512_256:
            return oidHMACWithSHA512_256, nil
        case SM3:
            return oidHMACWithSM3, nil
        case GOST34112012256:
            return oidHMACWithGOST34112012256, nil
        case GOST34112012512:
            return oidHMACWithGOST34112012512, nil
    }

    return nil, errors.New("go-cryptobin/pkcs8: unsupported hash function")
}

// pbkdf2 数据，作为包装
type pbkdf2Params struct {
    Salt           []byte
    IterationCount int
    KeyLength      int `asn1:"optional"`
    PrfParam       pkix.AlgorithmIdentifier `asn1:"optional"`
}

func (this pbkdf2Params) PBESOID() asn1.ObjectIdentifier {
    return oidPBES2
}

func (this pbkdf2Params) DeriveKey(password []byte, size int) (key []byte, err error) {
    var alg asn1.ObjectIdentifier
    var h func() hash.Hash

    // 如果有自定义长度，使用自定义长度
    if this.KeyLength > 0 {
        size = this.KeyLength
    }

    if this.PrfParam.Algorithm.String() != "" {
        h, err = prfByOID(this.PrfParam.Algorithm)
        if err != nil {
            return nil, err
        }
    } else {
        alg, err = oidByHash(DefaultHash)
        if err != nil {
            return nil, err
        }

        h, err = prfByOID(alg)
        if err != nil {
            return nil, err
        }
    }

    key = pbkdf2.Key(password, this.Salt, this.IterationCount, size, h)

    return
}

// PBKDF2 配置
type PBKDF2Opts struct {
    hasKeyLength   bool
    SaltSize       int
    IterationCount int
    HMACHash       Hash
}

func (this PBKDF2Opts) GetSaltSize() int {
    return this.SaltSize
}

func (this PBKDF2Opts) OID() asn1.ObjectIdentifier {
    return oidPKCS5PBKDF2
}

func (this PBKDF2Opts) PBESOID() asn1.ObjectIdentifier {
    return oidPBES2
}

func (this PBKDF2Opts) WithHasKeyLength(hasKeyLength bool) KDFOpts {
    this.hasKeyLength = hasKeyLength

    return this
}

func (this PBKDF2Opts) DeriveKey(password, salt []byte, size int) (key []byte, params KDFParameters, err error) {
    var alg asn1.ObjectIdentifier
    var prfParam pkix.AlgorithmIdentifier

    if this.HMACHash != 0 {
        alg, err = oidByHash(this.HMACHash)
        if err != nil {
            return nil, nil, err
        }

        prfParam = pkix.AlgorithmIdentifier{
            Algorithm:  alg,
            Parameters: asn1.RawValue{
                Tag: asn1.TagNull,
            },
        }
    } else {
        alg, err = oidByHash(DefaultHash)
        if err != nil {
            return nil, nil, err
        }

        prfParam = pkix.AlgorithmIdentifier{}
    }

    h, err := prfByOID(alg)
    if err != nil {
        return nil, nil, err
    }

    parameters := pbkdf2Params{
        Salt:           salt,
        IterationCount: this.IterationCount,
        PrfParam:       prfParam,
    }

    // 设置 KeyLength
    if this.hasKeyLength {
        parameters.KeyLength = size
    }

    key = pbkdf2.Key(password, salt, this.IterationCount, size, h)

    return key, parameters, nil
}

func init() {
    AddKDF(oidPKCS5PBKDF2, func() KDFParameters {
        return new(pbkdf2Params)
    })
}
