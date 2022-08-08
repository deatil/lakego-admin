package pkcs8

import (
    "encoding/asn1"

    "golang.org/x/crypto/scrypt"
)

var (
    oidScrypt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
)

// scrypt 数据
type scryptParams struct {
    Salt                     []byte
    CostParameter            int
    BlockSize                int
    ParallelizationParameter int
}

func (this scryptParams) DeriveKey(password []byte, size int) (key []byte, err error) {
    return scrypt.Key(
        password, this.Salt,
        this.CostParameter, this.BlockSize,
        this.ParallelizationParameter, size,
    )
}

// ScryptOpts 设置
type ScryptOpts struct {
    SaltSize                 int
    CostParameter            int
    BlockSize                int
    ParallelizationParameter int
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

    params = scryptParams{
        BlockSize:                this.BlockSize,
        CostParameter:            this.CostParameter,
        ParallelizationParameter: this.ParallelizationParameter,
        Salt:                     salt,
    }

    return key, params, nil
}

func (this ScryptOpts) GetSaltSize() int {
    return this.SaltSize
}

func (this ScryptOpts) OID() asn1.ObjectIdentifier {
    return oidScrypt
}

func init() {
    AddKDF(oidScrypt, func() KDFParameters {
        return new(scryptParams)
    })
}
