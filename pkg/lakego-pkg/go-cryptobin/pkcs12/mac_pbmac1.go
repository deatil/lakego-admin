package pkcs12

import (
    "fmt"
    "hash"
    "errors"
    "crypto/rand"
    "crypto/hmac"
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

// see https://datatracker.ietf.org/doc/html/rfc9579

type PBMAC1Hash uint

const (
    PBMAC1_MD5 PBMAC1Hash = 1 + iota
    PBMAC1_SHA1
    PBMAC1_SHA224
    PBMAC1_SHA256
    PBMAC1_SHA384
    PBMAC1_SHA512
    PBMAC1_SHA512_224
    PBMAC1_SHA512_256
    PBMAC1_SM3
    PBMAC1_GOST34112012256
    PBMAC1_GOST34112012512
)

var (
    // 默认 PBMAC1 hash
    DefaultPBMAC1Hash = PBMAC1_SHA1
)

var (
    // PKCS12-PBMAC1
    oidPBMAC1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}

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
func prfByOIDPBMAC1(oid asn1.ObjectIdentifier) (func() hash.Hash, error) {
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

    return nil, fmt.Errorf("pkcs12: unsupported hash (OID: %s)", oid)
}

// 返回使用的 Hash 对应的 asn1
func oidByHashPBMAC1(h PBMAC1Hash) (asn1.ObjectIdentifier, error) {
    switch h {
        case PBMAC1_MD5:
            return oidHMACWithMD5, nil
        case PBMAC1_SHA1:
            return oidHMACWithSHA1, nil
        case PBMAC1_SHA224:
            return oidHMACWithSHA224, nil
        case PBMAC1_SHA256:
            return oidHMACWithSHA256, nil
        case PBMAC1_SHA384:
            return oidHMACWithSHA384, nil
        case PBMAC1_SHA512:
            return oidHMACWithSHA512, nil
        case PBMAC1_SHA512_224:
            return oidHMACWithSHA512_224, nil
        case PBMAC1_SHA512_256:
            return oidHMACWithSHA512_256, nil
        case PBMAC1_SM3:
            return oidHMACWithSM3, nil
        case PBMAC1_GOST34112012256:
            return oidHMACWithGOST34112012256, nil
        case PBMAC1_GOST34112012512:
            return oidHMACWithGOST34112012512, nil
    }

    return nil, errors.New("pkcs12: unsupported hash function")
}

//  PBMAC1-params ::= SEQUENCE {
//      keyDerivationFunc AlgorithmIdentifier {{PBMAC1-KDFs}},
//      messageAuthScheme AlgorithmIdentifier {{PBMAC1-MACs}}
//  }
type pbmac1Params struct {
    Kdf               pkix.AlgorithmIdentifier
    MessageAuthScheme pkix.AlgorithmIdentifier
}

// pbkdf2 数据，作为包装
type pbkdf2Params struct {
    Salt           []byte
    IterationCount int
    KeyLength      int `asn1:"optional"`
    PrfParam       pkix.AlgorithmIdentifier `asn1:"optional"`
}

func (this pbkdf2Params) DeriveKey(password []byte) (key []byte, err error) {
    var alg asn1.ObjectIdentifier
    var h func() hash.Hash

    if this.PrfParam.Algorithm.String() != "" {
        h, err = prfByOIDPBMAC1(this.PrfParam.Algorithm)
        if err != nil {
            return nil, err
        }
    } else {
        alg, err = oidByHashPBMAC1(DefaultPBMAC1Hash)
        if err != nil {
            return nil, err
        }

        h, err = prfByOIDPBMAC1(alg)
        if err != nil {
            return nil, err
        }
    }

    size := h().Size()

    // 如果有自定义长度，使用自定义长度
    if this.KeyLength > 0 {
        size = this.KeyLength
    }

    key = pbkdf2.Key(password, this.Salt, this.IterationCount, size, h)

    return
}

func parsePBMAC1Param(param []byte, password []byte) (h func() hash.Hash, key []byte, err error) {
    var params pbmac1Params
    if err = unmarshal(param, &params); err != nil {
        return
    }

    var kdfparams pbkdf2Params
    if err = unmarshal(params.Kdf.Parameters.FullBytes, &kdfparams); err != nil {
        return
    }

    originalPassword, err := decodeBMPString(password)
    if err != nil {
        return
    }

    h, err = prfByOIDPBMAC1(params.MessageAuthScheme.Algorithm)
    if err != nil {
        return
    }

    key, err = kdfparams.DeriveKey([]byte(originalPassword))
    if err != nil {
        return
    }

    return
}

// PBMAC1 配置
type PBMAC1Opts struct {
    hasKeyLength   bool
    SaltSize       int
    IterationCount int
    KDFHash        PBMAC1Hash
    HMACHash       PBMAC1Hash
}

func (this PBMAC1Opts) Compute(message []byte, password []byte) (data MacKDFParameters, err error) {
    // hmac hash
    alg, err := oidByHashPBMAC1(this.HMACHash)
    if err != nil {
        return nil, err
    }

    h, err := prfByOIDPBMAC1(alg)
    if err != nil {
        return nil, err
    }

    key, kdf, err := this.computeKDF(password)
    if err != nil {
        return nil, err
    }

    var params pbmac1Params
    params.Kdf = pkix.AlgorithmIdentifier{
        Algorithm:  oidPKCS5PBKDF2,
        Parameters: asn1.RawValue{
            FullBytes: kdf,
        },
    }
    params.MessageAuthScheme = pkix.AlgorithmIdentifier{
        Algorithm:  alg,
        Parameters: asn1.RawValue{
            Tag: asn1.TagNull,
        },
    }

    encodedParams, err := asn1.Marshal(params)
    if err != nil {
        return nil, err
    }

    prfParam := pkix.AlgorithmIdentifier{
        Algorithm:  oidPBMAC1,
        Parameters: asn1.RawValue{
            FullBytes: encodedParams,
        },
    }

    mac := hmac.New(h, key)
    mac.Write(message)
    digest := mac.Sum(nil)

    data = MacData{
        Mac: DigestInfo{
            Algorithm: prfParam,
            Digest:    digest,
        },
        MacSalt: []byte("NOT USED"),
        Iterations: 1,
    }

    return
}

func (this PBMAC1Opts) computeKDF(password []byte) (key []byte, kdf []byte, err error) {
    var alg asn1.ObjectIdentifier
    var prfParam pkix.AlgorithmIdentifier

    if this.KDFHash != 0 {
        alg, err = oidByHashPBMAC1(this.KDFHash)
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
        alg, err = oidByHashPBMAC1(DefaultPBMAC1Hash)
        if err != nil {
            return nil, nil, err
        }

        prfParam = pkix.AlgorithmIdentifier{}
    }

    h, err := prfByOIDPBMAC1(alg)
    if err != nil {
        return nil, nil, err
    }

    salt := make([]byte, this.SaltSize)
    if _, err = rand.Read(salt); err != nil {
        return nil, nil, err
    }

    size := h().Size()

    kdfParams := pbkdf2Params{
        Salt:           salt,
        IterationCount: this.IterationCount,
        PrfParam:       prfParam,
    }

    // 设置 KeyLength
    if this.hasKeyLength {
        kdfParams.KeyLength = size
    }

    kdf, err = asn1.Marshal(kdfParams)
    if err != nil {
        return nil, nil, err
    }

    originalPassword, err := decodeBMPString(password)
    if err != nil {
        return nil, nil, err
    }

    key = pbkdf2.Key([]byte(originalPassword), salt, this.IterationCount, size, h)

    return
}
