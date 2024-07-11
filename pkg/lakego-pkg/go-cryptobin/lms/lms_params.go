package lms

import (
    "crypto/sha256"

    "github.com/deatil/go-cryptobin/hash/sm3"
)

type LmsType uint32

const (
    LMS_SHA256_M32_H5  LmsType = 5
    LMS_SHA256_M32_H10 LmsType = 6
    LMS_SHA256_M32_H15 LmsType = 7
    LMS_SHA256_M32_H20 LmsType = 8
    LMS_SHA256_M32_H25 LmsType = 9

    LMS_SM3_M32_H5  LmsType = 25
    LMS_SM3_M32_H10 LmsType = 26
    LMS_SM3_M32_H15 LmsType = 27
    LMS_SM3_M32_H20 LmsType = 28
    LMS_SM3_M32_H25 LmsType = 29
)

// ILmsParam represents a specific instance of LMS
type ILmsParam interface {
    GetType() LmsType
    SigLength(ILmotsParam) uint64
    Params() LmsParam
}

type LmsParam struct {
    Type LmsType
    Hash Hasher
    M    uint64
    H    uint64
}

// Returns a uint32 of the same value as the LmsType
func (this LmsParam) GetType() LmsType {
    return this.Type
}

// Returns the expected byte length of a given LMS signature algorithm
func (this LmsParam) SigLength(otstc ILmotsParam) uint64 {
    otsSigLen := otstc.SigLength()

    return uint64(4 + 4) + otsSigLen + (this.H * this.M)
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
    LMS_SHA256_M32_H5_Param = LmsParam{
        Type: LMS_SHA256_M32_H5,
        Hash: sha256.New,
        M:    32,
        H:    5,
    }
    LMS_SHA256_M32_H10_Param = LmsParam{
        Type: LMS_SHA256_M32_H10,
        Hash: sha256.New,
        M:    32,
        H:    10,
    }
    LMS_SHA256_M32_H15_Param = LmsParam{
        Type: LMS_SHA256_M32_H15,
        Hash: sha256.New,
        M:    32,
        H:    15,
    }
    LMS_SHA256_M32_H20_Param = LmsParam{
        Type: LMS_SHA256_M32_H20,
        Hash: sha256.New,
        M:    32,
        H:    20,
    }
    LMS_SHA256_M32_H25_Param = LmsParam{
        Type: LMS_SHA256_M32_H25,
        Hash: sha256.New,
        M:    32,
        H:    25,
    }

    // SM3
    LMS_SM3_M32_H5_Param = LmsParam{
        Type: LMS_SM3_M32_H5,
        Hash: sm3.New,
        M:    32,
        H:    5,
    }
    LMS_SM3_M32_H10_Param = LmsParam{
        Type: LMS_SM3_M32_H10,
        Hash: sm3.New,
        M:    32,
        H:    10,
    }
    LMS_SM3_M32_H15_Param = LmsParam{
        Type: LMS_SM3_M32_H15,
        Hash: sm3.New,
        M:    32,
        H:    15,
    }
    LMS_SM3_M32_H20_Param = LmsParam{
        Type: LMS_SM3_M32_H20,
        Hash: sm3.New,
        M:    32,
        H:    20,
    }
    LMS_SM3_M32_H25_Param = LmsParam{
        Type: LMS_SM3_M32_H25,
        Hash: sm3.New,
        M:    32,
        H:    25,
    }

)

func init() {
    AddLmsParam(LMS_SHA256_M32_H5_Param.Type, func() ILmsParam {
        return LMS_SHA256_M32_H5_Param
    })
    AddLmsParam(LMS_SHA256_M32_H10_Param.Type, func() ILmsParam {
        return LMS_SHA256_M32_H10_Param
    })
    AddLmsParam(LMS_SHA256_M32_H15_Param.Type, func() ILmsParam {
        return LMS_SHA256_M32_H15_Param
    })
    AddLmsParam(LMS_SHA256_M32_H20_Param.Type, func() ILmsParam {
        return LMS_SHA256_M32_H20_Param
    })
    AddLmsParam(LMS_SHA256_M32_H25_Param.Type, func() ILmsParam {
        return LMS_SHA256_M32_H25_Param
    })

    // SM3
    AddLmsParam(LMS_SM3_M32_H5_Param.Type, func() ILmsParam {
        return LMS_SM3_M32_H5_Param
    })
    AddLmsParam(LMS_SM3_M32_H10_Param.Type, func() ILmsParam {
        return LMS_SM3_M32_H10_Param
    })
    AddLmsParam(LMS_SM3_M32_H15_Param.Type, func() ILmsParam {
        return LMS_SM3_M32_H15_Param
    })
    AddLmsParam(LMS_SM3_M32_H20_Param.Type, func() ILmsParam {
        return LMS_SM3_M32_H20_Param
    })
    AddLmsParam(LMS_SM3_M32_H25_Param.Type, func() ILmsParam {
        return LMS_SM3_M32_H25_Param
    })

}
