package lms

import (
    "crypto/sha256"

    "github.com/deatil/go-cryptobin/hash/sm3"
)

type LmsType uint32

const (
    type_LMS_SHA256_M32_H5  LmsType = 5
    type_LMS_SHA256_M32_H10 LmsType = 6
    type_LMS_SHA256_M32_H15 LmsType = 7
    type_LMS_SHA256_M32_H20 LmsType = 8
    type_LMS_SHA256_M32_H25 LmsType = 9

    type_LMS_SM3_M32_H5  LmsType = 25
    type_LMS_SM3_M32_H10 LmsType = 26
    type_LMS_SM3_M32_H15 LmsType = 27
    type_LMS_SM3_M32_H20 LmsType = 28
    type_LMS_SM3_M32_H25 LmsType = 29
)

// ILmsParam represents a specific instance of LMS
type ILmsParam interface {
    GetType() LmsType
    SigLength(ILmotsParam) uint64
    Params() LmsParam
}

type LmsParam struct {
    Name string
    Type LmsType
    Hash Hasher
    M    uint64
    H    uint64
}

// Returns a param name string
func (this LmsParam) String() string {
    return this.Name
}

// Returns a uint32 of the same value as the LmsType
func (this LmsParam) GetType() LmsType {
    return this.Type
}

// Returns the expected byte length of a given LMS signature algorithm
func (this LmsParam) SigLength(otstc ILmotsParam) uint64 {
    otsSigLen := otstc.SigLength()

    return 4 + 4 + otsSigLen + (this.H * this.M)
}

// Returns a Params
func (this LmsParam) Params() LmsParam {
    return this
}

// ===============

// default
var defaultLmsParams = NewTypeParams[LmsType, ILmsParam]()

// AddLmsParam
func AddLmsParam(typ LmsType, fn func() ILmsParam) {
    defaultLmsParams.AddParam(typ, fn)
}

// GetLmsParam
func GetLmsParam(typ LmsType) (func() ILmsParam, error) {
    return defaultLmsParams.GetParam(typ)
}

// AllLmsParams
func AllLmsParams() map[LmsType]func() ILmsParam {
    return defaultLmsParams.AllParams()
}

// ===============

var (
    LMS_SHA256_M32_H5 = LmsParam{
        Name: "LMS_SHA256_M32_H5",
        Type: type_LMS_SHA256_M32_H5,
        Hash: sha256.New,
        M:    32,
        H:    5,
    }
    LMS_SHA256_M32_H10 = LmsParam{
        Name: "LMS_SHA256_M32_H10",
        Type: type_LMS_SHA256_M32_H10,
        Hash: sha256.New,
        M:    32,
        H:    10,
    }
    LMS_SHA256_M32_H15 = LmsParam{
        Name: "LMS_SHA256_M32_H15",
        Type: type_LMS_SHA256_M32_H15,
        Hash: sha256.New,
        M:    32,
        H:    15,
    }
    LMS_SHA256_M32_H20 = LmsParam{
        Name: "LMS_SHA256_M32_H20",
        Type: type_LMS_SHA256_M32_H20,
        Hash: sha256.New,
        M:    32,
        H:    20,
    }
    LMS_SHA256_M32_H25 = LmsParam{
        Name: "LMS_SHA256_M32_H25",
        Type: type_LMS_SHA256_M32_H25,
        Hash: sha256.New,
        M:    32,
        H:    25,
    }

    // SM3
    LMS_SM3_M32_H5 = LmsParam{
        Name: "LMS_SM3_M32_H5",
        Type: type_LMS_SM3_M32_H5,
        Hash: sm3.New,
        M:    32,
        H:    5,
    }
    LMS_SM3_M32_H10 = LmsParam{
        Name: "LMS_SM3_M32_H10",
        Type: type_LMS_SM3_M32_H10,
        Hash: sm3.New,
        M:    32,
        H:    10,
    }
    LMS_SM3_M32_H15 = LmsParam{
        Name: "LMS_SM3_M32_H15",
        Type: type_LMS_SM3_M32_H15,
        Hash: sm3.New,
        M:    32,
        H:    15,
    }
    LMS_SM3_M32_H20 = LmsParam{
        Name: "LMS_SM3_M32_H20",
        Type: type_LMS_SM3_M32_H20,
        Hash: sm3.New,
        M:    32,
        H:    20,
    }
    LMS_SM3_M32_H25 = LmsParam{
        Name: "LMS_SM3_M32_H25",
        Type: type_LMS_SM3_M32_H25,
        Hash: sm3.New,
        M:    32,
        H:    25,
    }

)

func init() {
    AddLmsParam(LMS_SHA256_M32_H5.Type, func() ILmsParam {
        return LMS_SHA256_M32_H5
    })
    AddLmsParam(LMS_SHA256_M32_H10.Type, func() ILmsParam {
        return LMS_SHA256_M32_H10
    })
    AddLmsParam(LMS_SHA256_M32_H15.Type, func() ILmsParam {
        return LMS_SHA256_M32_H15
    })
    AddLmsParam(LMS_SHA256_M32_H20.Type, func() ILmsParam {
        return LMS_SHA256_M32_H20
    })
    AddLmsParam(LMS_SHA256_M32_H25.Type, func() ILmsParam {
        return LMS_SHA256_M32_H25
    })

    // SM3
    AddLmsParam(LMS_SM3_M32_H5.Type, func() ILmsParam {
        return LMS_SM3_M32_H5
    })
    AddLmsParam(LMS_SM3_M32_H10.Type, func() ILmsParam {
        return LMS_SM3_M32_H10
    })
    AddLmsParam(LMS_SM3_M32_H15.Type, func() ILmsParam {
        return LMS_SM3_M32_H15
    })
    AddLmsParam(LMS_SM3_M32_H20.Type, func() ILmsParam {
        return LMS_SM3_M32_H20
    })
    AddLmsParam(LMS_SM3_M32_H25.Type, func() ILmsParam {
        return LMS_SM3_M32_H25
    })

}
