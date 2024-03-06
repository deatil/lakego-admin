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

    "github.com/deatil/go-cryptobin/kdf/pbkdf"
    "github.com/deatil/go-cryptobin/kdf/gost_pbkdf2"
    "github.com/deatil/go-cryptobin/hash/md2"
    "github.com/deatil/go-cryptobin/hash/sm3"
    "github.com/deatil/go-cryptobin/hash/gost/gost34112012256"
    "github.com/deatil/go-cryptobin/hash/gost/gost34112012512"
)

// 可使用的 hash 方式
type Hash uint

const (
    MD2 Hash = 1 + iota
    MD4
    MD5
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
    oidMD2        = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 2}
    oidMD4        = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 4}
    oidMD5        = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
    oidSHA1       = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
    oidSHA224     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
    oidSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
    oidSHA384     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
    oidSHA512     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
    oidSHA512_224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 5}
    oidSHA512_256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 6}
    oidSM3        = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}

    oidGOST34112012256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
    oidGOST34112012512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 3}
)

// 返回使用的 Hash 方式
func hashByOID(oid asn1.ObjectIdentifier) (func() hash.Hash, error) {
    switch {
        case oid.Equal(oidMD2):
            return md2.New, nil
        case oid.Equal(oidMD4):
            return md4.New, nil
        case oid.Equal(oidMD5):
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
        case oid.Equal(oidSHA512_224):
            return sha512.New512_224, nil
        case oid.Equal(oidSHA512_256):
            return sha512.New512_256, nil
        case oid.Equal(oidSM3):
            return sm3.New, nil
        case oid.Equal(oidGOST34112012256):
            return gost34112012256.New, nil
        case oid.Equal(oidGOST34112012512):
            return gost34112012512.New, nil
    }

    return nil, errors.New("pkcs12: unsupported hash function")
}

// 返回使用的 Hash 对应的 asn1
func oidByHash(h Hash) (asn1.ObjectIdentifier, error) {
    switch h {
        case MD2:
            return oidMD2, nil
        case MD4:
            return oidMD4, nil
        case MD5:
            return oidMD5, nil
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
        case SHA512_224:
            return oidSHA512_224, nil
        case SHA512_256:
            return oidSHA512_256, nil
        case SM3:
            return oidSM3, nil
        case GOST34112012256:
            return oidGOST34112012256, nil
        case GOST34112012512:
            return oidGOST34112012512, nil
    }

    return nil, errors.New("pkcs12: unsupported hash function")
}

// from PKCS#7:
type DigestInfo struct {
    Algorithm pkix.AlgorithmIdentifier
    Digest    []byte
}

type MacData struct {
    Mac        DigestInfo
    MacSalt    []byte
    Iterations int `asn1:"optional,default:1"`
}

func (this MacData) Verify(message []byte, password []byte) (err error) {
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

    oid := this.Mac.Algorithm.Algorithm

    var key []byte
    switch {
        case oid.Equal(oidGOST34112012256),
            oid.Equal(oidGOST34112012512):
            pass, err := decodeBMPString(password)
            if err != nil {
                return err
            }

            key = gost_pbkdf2.Key(h, []byte(pass), this.MacSalt, this.Iterations, 96)
            key = key[len(key)-32:]
        default:
            hashSize := h().Size()

            key = pbkdf.Key(h, hashSize, 64, this.MacSalt, password, this.Iterations, 3, hashSize)
    }

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

func (this MacOpts) Compute(message []byte, password []byte) (data MacKDFParameters, err error) {
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

    var key []byte
    switch {
        case alg.Equal(oidGOST34112012256),
            alg.Equal(oidGOST34112012512):
            pass, err := decodeBMPString(password)
            if err != nil {
                return nil, err
            }

            key = gost_pbkdf2.Key(h, []byte(pass), macSalt, this.IterationCount, 96)
            key = key[len(key)-32:]
        default:
            hashSize := h().Size()

            key = pbkdf.Key(h, hashSize, 64, macSalt, password, this.IterationCount, 3, hashSize)
    }

    mac := hmac.New(h, key)
    mac.Write(message)
    digest := mac.Sum(nil)

    data = MacData{
        DigestInfo{
            prfParam,
            digest,
        },
        macSalt,
        this.IterationCount,
    }

    return
}
