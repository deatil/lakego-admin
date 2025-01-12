package pbes2

import (
    "encoding/asn1"

    "golang.org/x/crypto/scrypt"
)

var (
    oidScrypt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
)

// scrypt params
type scryptParams struct {
    Salt                     []byte
    CostParameter            int
    BlockSize                int
    ParallelizationParameter int
    KeyLength                int `asn1:"optional"`
}

func (this scryptParams) PBESOID() asn1.ObjectIdentifier {
    return oidPBES2
}

func (this scryptParams) DeriveKey(password []byte, size int) (key []byte, err error) {
    // 如果有自定义长度，使用自定义长度
    if this.KeyLength > 0 {
        size = this.KeyLength
    }

    return scrypt.Key(
        password, this.Salt,
        this.CostParameter, this.BlockSize,
        this.ParallelizationParameter, size,
    )
}

// Scrypt options
type ScryptOpts struct {
    hasKeyLength             bool
    SaltSize                 int
    CostParameter            int
    BlockSize                int
    ParallelizationParameter int
}

func (this ScryptOpts) GetSaltSize() int {
    return this.SaltSize
}

func (this ScryptOpts) OID() asn1.ObjectIdentifier {
    return oidScrypt
}

func (this ScryptOpts) PBESOID() asn1.ObjectIdentifier {
    return oidPBES2
}

func (this ScryptOpts) WithHasKeyLength(hasKeyLength bool) KDFOpts {
    this.hasKeyLength = hasKeyLength

    return this
}

func (this ScryptOpts) DeriveKey(password, salt []byte, size int) (key []byte, params KDFParameters, err error) {
    key, err = scrypt.Key(
        password, salt,
        this.CostParameter, this.BlockSize,
        this.ParallelizationParameter, size,
    )
    if err != nil {
        return nil, nil, err
    }

    parameters := scryptParams{
        BlockSize:                this.BlockSize,
        CostParameter:            this.CostParameter,
        ParallelizationParameter: this.ParallelizationParameter,
        Salt:                     salt,
    }

    // 设置 KeyLength
    if this.hasKeyLength {
        parameters.KeyLength = size
    }

    return key, parameters, nil
}

func init() {
    AddKDF(oidScrypt, func() KDFParameters {
        return new(scryptParams)
    })
}
