package pkcs12

import (
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

    "golang.org/x/crypto/md4"
    "github.com/tjfoc/gmsm/sm3"

    cryptobin_md2 "github.com/deatil/go-cryptobin/hash/md2"
    cryptobin_pbkdf "github.com/deatil/go-cryptobin/kdf/pbkdf"
)

// pkcs8 可使用的 hash 方式
type Hash uint

const (
    Md2 Hash = 1 + iota
    Md4
    MD5
    SHA1
    SHA224
    SHA256
    SHA384
    SHA512
    SM3
)

var (
    // 默认 hash
    DefaultHash = SHA1
)

var (
    oidSMd2   = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 2, 2})
    oidSMd4   = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 2, 4})
    oidSMd5   = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 2, 5})
    oidSHA1   = asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26})
    oidSHA224 = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 4})
    oidSHA256 = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1})
    oidSHA384 = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 2})
    oidSHA512 = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 3})
    oidSM3    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}
)

// 返回使用的 Hash 方式
func hashByOID(oid asn1.ObjectIdentifier) (func() hash.Hash, error) {
    switch {
        case oid.Equal(oidSMd2):
            return cryptobin_md2.New, nil
        case oid.Equal(oidSMd4):
            return md4.New, nil
        case oid.Equal(oidSMd5):
            return md5.New, nil
        case oid.Equal(oidSHA1):
            return sha1.New, nil
        case oid.Equal(oidSHA224):
            return sha256.New224, nil
        case oid.Equal(oidSHA256):
            return sha256.New, nil
        case oid.Equal(oidSHA384):
            return sha512.New384, nil
        case oid.Equal(oidSHA512):
            return sha512.New, nil
        case oid.Equal(oidSM3):
            return sm3.New, nil
    }

    return nil, errors.New("pkcs12: unsupported hash function")
}

// 返回使用的 Hash 对应的 asn1
func oidByHash(h Hash) (asn1.ObjectIdentifier, error) {
    switch h {
        case Md2:
            return oidSMd2, nil
        case Md4:
            return oidSMd4, nil
        case MD5:
            return oidSMd5, nil
        case SHA1:
            return oidSHA1, nil
        case SHA224:
            return oidSHA224, nil
        case SHA256:
            return oidSHA256, nil
        case SHA384:
            return oidSHA384, nil
        case SHA512:
            return oidSHA512, nil
        case SM3:
            return oidSM3, nil
    }

    return nil, errors.New("pkcs12: unsupported hash function")
}

// from PKCS#7:
type digestInfo struct {
    Algorithm pkix.AlgorithmIdentifier
    Digest    []byte
}

type macData struct {
    Mac        digestInfo
    MacSalt    []byte
    Iterations int `asn1:"optional,default:1"`
}

func (this macData) Verify(message []byte, password []byte) (err error) {
    var alg asn1.ObjectIdentifier
    var h func() hash.Hash

    if this.Mac.Algorithm.Algorithm.String() != "" {
        h, err = hashByOID(this.Mac.Algorithm.Algorithm)
        if err != nil {
            return err
        }
    } else {
        alg, err = oidByHash(DefaultHash)
        if err != nil {
            return err
        }

        h, err = hashByOID(alg)
        if err != nil {
            return err
        }
    }

    hashSize := h().Size()

    key := cryptobin_pbkdf.Key(h, hashSize, 64, this.MacSalt, password, this.Iterations, 3, hashSize)

    mac := hmac.New(h, key)
    mac.Write(message)
    expectedMAC := mac.Sum(nil)

    if !hmac.Equal(this.Mac.Digest, expectedMAC) {
        return ErrIncorrectPassword
    }

    return
}

// mac 配置
type MacOpts struct {
    SaltSize       int // 8
    IterationCount int // 1
    HMACHash       Hash
}

func (this MacOpts) Compute(message []byte, password []byte) (data KDFParameters, err error) {
    var alg asn1.ObjectIdentifier
    var prfParam pkix.AlgorithmIdentifier

    if this.HMACHash != 0 {
        alg, err = oidByHash(this.HMACHash)
    } else {
        alg, err = oidByHash(DefaultHash)
    }

    if err != nil {
        return nil, err
    }

    prfParam = pkix.AlgorithmIdentifier{
        Algorithm:  alg,
        Parameters: asn1.RawValue{
            Tag: asn1.TagNull,
        },
    }

    h, err := hashByOID(alg)
    if err != nil {
        return nil, err
    }

    macSalt := make([]byte, this.SaltSize)
    if _, err = rand.Read(macSalt); err != nil {
        return nil, err
    }

    hashSize := h().Size()

    key := cryptobin_pbkdf.Key(sha1.New, hashSize, 64, macSalt, password, this.IterationCount, 3, hashSize)

    mac := hmac.New(h, key)
    mac.Write(message)
    digest := mac.Sum(nil)

    data = macData{
        digestInfo{
            prfParam,
            digest,
        },
        macSalt,
        this.IterationCount,
    }

    return
}
