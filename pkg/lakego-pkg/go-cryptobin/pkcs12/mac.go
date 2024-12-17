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
    "crypto/cipher"
    "encoding/asn1"

    "golang.org/x/crypto/md4"

    "github.com/deatil/go-cryptobin/kdf/pbkdf"
    "github.com/deatil/go-cryptobin/kdf/gost_pbkdf2"
    "github.com/deatil/go-cryptobin/hash/md2"
    "github.com/deatil/go-cryptobin/hash/sm3"
    "github.com/deatil/go-cryptobin/hash/gost/gost341194"
    "github.com/deatil/go-cryptobin/hash/gost/gost34112012256"
    "github.com/deatil/go-cryptobin/hash/gost/gost34112012512"
    cipher_gost "github.com/deatil/go-cryptobin/cipher/gost"
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
    GOST341194
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

    oidGOST341194      = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 10}
    oidGOST34112012256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
    oidGOST34112012512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 3}
)

// (that is, H has a chaining variable and output of length u bits, and
// the message input to the compression function of H is v bits).  The
// values for u and v are as follows:
//            HASH FUNCTION     VALUE u        VALUE v
//              MD2, MD5          128            512
//                SHA-1           160            512
//               SHA-224          224            512
//               SHA-256          256            512
//               SHA-384          384            1024
//               SHA-512          512            1024
//             SHA-512/224        224            1024
//             SHA-512/256        256            1024

// 返回使用的 Hash
// return hash from oid
func hashByOID(oid asn1.ObjectIdentifier) (func() hash.Hash, int, error) {
    switch {
        case oid.Equal(oidMD2):
            return md2.New, 64, nil
        case oid.Equal(oidMD4):
            return md4.New, 64, nil
        case oid.Equal(oidMD5):
            return md5.New, 64, nil
        case oid.Equal(oidSHA1):
            return sha1.New, 64, nil
        case oid.Equal(oidSHA224):
            return sha256.New224, 64, nil
        case oid.Equal(oidSHA256):
            return sha256.New, 64, nil
        case oid.Equal(oidSHA384):
            return sha512.New384, 128, nil
        case oid.Equal(oidSHA512):
            return sha512.New, 128, nil
        case oid.Equal(oidSHA512_224):
            return sha512.New512_224, 128, nil
        case oid.Equal(oidSHA512_256):
            return sha512.New512_256, 128, nil
        case oid.Equal(oidSM3):
            return sm3.New, 64, nil
        case oid.Equal(oidGOST341194):
            return newGOST341194Hash, 64, nil
        case oid.Equal(oidGOST34112012256):
            return gost34112012256.New, 64, nil
        case oid.Equal(oidGOST34112012512):
            return gost34112012512.New, 128, nil
    }

    return nil, 0, fmt.Errorf("go-cryptobin/pkcs12: unsupported hash (OID: %s)", oid)
}

// 返回使用的 Hash 对应的 oid
// return oid from hash type
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
        case GOST341194:
            return oidGOST341194, nil
        case GOST34112012256:
            return oidGOST34112012256, nil
        case GOST34112012512:
            return oidGOST34112012512, nil
    }

    return nil, errors.New("go-cryptobin/pkcs12: unsupported hash function")
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
    var h func() hash.Hash
    var key []byte

    switch {
        case this.Mac.Algorithm.Algorithm.Equal(oidPBMAC1):
            h, key, err = parsePBMAC1Param(this.Mac.Algorithm.Parameters.FullBytes, password)
            if err != nil {
                return err
            }
        default:
            h, key, err = this.parseMacParam(password)
            if err != nil {
                return err
            }
    }

    mac := hmac.New(h, key)
    mac.Write(message)
    expectedMAC := mac.Sum(nil)

    if !hmac.Equal(this.Mac.Digest, expectedMAC) {
        return ErrIncorrectPassword
    }

    return
}

func (this MacData) parseMacParam(password []byte) (h func() hash.Hash, key []byte, err error) {
    var alg asn1.ObjectIdentifier

    oid := this.Mac.Algorithm.Algorithm

    var v int

    if oid.String() != "" {
        h, v, err = hashByOID(oid)
        if err != nil {
            return
        }
    } else {
        alg, err = oidByHash(DefaultHash)
        if err != nil {
            return
        }

        h, v, err = hashByOID(alg)
        if err != nil {
            return
        }
    }

    switch {
        case oid.Equal(oidGOST341194),
            oid.Equal(oidGOST34112012256),
            oid.Equal(oidGOST34112012512):
            pass, err := decodeBMPString(password)
            if err != nil {
                return nil, nil, err
            }

            key = gost_pbkdf2.Key(h, []byte(pass), this.MacSalt, this.Iterations, 96)
            key = key[len(key)-32:]
        default:
            hashSize := h().Size()

            key = pbkdf.Key(h, hashSize, v, this.MacSalt, password, this.Iterations, 3, hashSize)
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

    h, v, err := hashByOID(alg)
    if err != nil {
        return nil, err
    }

    macSalt := make([]byte, this.SaltSize)
    if _, err = rand.Read(macSalt); err != nil {
        return nil, err
    }

    var key []byte
    switch {
        case alg.Equal(oidGOST341194),
            alg.Equal(oidGOST34112012256),
            alg.Equal(oidGOST34112012512):
            pass, err := decodeBMPString(password)
            if err != nil {
                return nil, err
            }

            key = gost_pbkdf2.Key(h, []byte(pass), macSalt, this.IterationCount, 96)
            key = key[len(key)-32:]
        default:
            hashSize := h().Size()

            key = pbkdf.Key(h, hashSize, v, macSalt, password, this.IterationCount, 3, hashSize)
    }

    mac := hmac.New(h, key)
    mac.Write(message)
    digest := mac.Sum(nil)

    data = MacData{
        Mac: DigestInfo{
            Algorithm: prfParam,
            Digest:    digest,
        },
        MacSalt:    macSalt,
        Iterations: this.IterationCount,
    }

    return
}

func newGOST341194Hash() hash.Hash {
    h := gost341194.New(func(key []byte) cipher.Block {
        cip, _ := cipher_gost.NewCipher(key, cipher_gost.SboxGostR341194CryptoProParamSet)

        return cip
    })

    return h
}
