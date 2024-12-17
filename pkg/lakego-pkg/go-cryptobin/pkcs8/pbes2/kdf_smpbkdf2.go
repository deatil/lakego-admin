package pbes2

import (
    "fmt"
    "hash"
    "errors"
    "crypto/x509/pkix"
    "encoding/asn1"

    "golang.org/x/crypto/pbkdf2"

    "github.com/deatil/go-cryptobin/hash/sm3"
)

var (
    // 默认 hash
    DefaultSMHash = SM3
)

var (
    // key derivation functions
    oidSMPBKDF2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 4, 1, 5, 1}
)

// 返回使用的 Hash 方式
func prfSMByOID(oid asn1.ObjectIdentifier) (func() hash.Hash, error) {
    switch {
        case oid.Equal(oidHMACWithSM3):
            return sm3.New, nil
    }

    return nil, fmt.Errorf("go-cryptobin/pkcs8: unsupported hash (OID: %s)", oid)
}

// 返回使用的 Hash 对应的 asn1
func oidSMByHash(h Hash) (asn1.ObjectIdentifier, error) {
    switch h {
        case SM3:
            return oidHMACWithSM3, nil
    }

    return nil, errors.New("go-cryptobin/pkcs8: unsupported hash function")
}

// smpbkdf2 数据，作为包装
type smpbkdf2Params struct {
    Salt           []byte
    IterationCount int
    KeyLength      int `asn1:"optional"`
    PrfParam       pkix.AlgorithmIdentifier `asn1:"optional"`
}

func (this smpbkdf2Params) PBESOID() asn1.ObjectIdentifier {
    return oidSMPBES2
}

func (this smpbkdf2Params) DeriveKey(password []byte, size int) (key []byte, err error) {
    var alg asn1.ObjectIdentifier
    var h func() hash.Hash

    // 如果有自定义长度，使用自定义长度
    if this.KeyLength > 0 {
        size = this.KeyLength
    }

    if this.PrfParam.Algorithm.String() != "" {
        h, err = prfSMByOID(this.PrfParam.Algorithm)
        if err != nil {
            return nil, err
        }
    } else {
        alg, err = oidSMByHash(DefaultSMHash)
        if err != nil {
            return nil, err
        }

        h, err = prfSMByOID(alg)
        if err != nil {
            return nil, err
        }
    }

    key = pbkdf2.Key(password, this.Salt, this.IterationCount, size, h)

    return
}

// GmSM PBKDF2 配置
type SMPBKDF2Opts struct {
    hasKeyLength   bool
    SaltSize       int
    IterationCount int
    HMACHash       Hash
}

func (this SMPBKDF2Opts) GetSaltSize() int {
    return this.SaltSize
}

func (this SMPBKDF2Opts) OID() asn1.ObjectIdentifier {
    return oidSMPBKDF2
}

func (this SMPBKDF2Opts) PBESOID() asn1.ObjectIdentifier {
    return oidSMPBES2
}

func (this SMPBKDF2Opts) WithHasKeyLength(hasKeyLength bool) KDFOpts {
    this.hasKeyLength = hasKeyLength

    return this
}

func (this SMPBKDF2Opts) DeriveKey(password, salt []byte, size int) (key []byte, params KDFParameters, err error) {
    var alg asn1.ObjectIdentifier
    var prfParam pkix.AlgorithmIdentifier

    if this.HMACHash != 0 {
        alg, err = oidSMByHash(this.HMACHash)
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
        alg, err = oidSMByHash(DefaultSMHash)
        if err != nil {
            return nil, nil, err
        }

        prfParam = pkix.AlgorithmIdentifier{}
    }

    h, err := prfSMByOID(alg)
    if err != nil {
        return nil, nil, err
    }

    parameters := smpbkdf2Params{
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
    AddKDF(oidSMPBKDF2, func() KDFParameters {
        return new(smpbkdf2Params)
    })
}
