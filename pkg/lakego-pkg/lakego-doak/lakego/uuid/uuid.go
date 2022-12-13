package uuid

import (
    "github.com/google/uuid"
)

type UUID = uuid.UUID

// 创建
func New() (UUID, error) {
    return uuid.NewRandom()
}

// uuid 字符
func ToUUIDString() string {
    v, err := New()

    if err != nil {
        return ""
    }

    return v.String()
}

// 出现错误抛出异常
func MustUUID() UUID {
    v, err := New()

    if err != nil {
        panic(err)
    }

    return v
}

// 创建会抛出异常的 uuid
func ToMustUUIDString() string {
    return MustUUID().String()
}
