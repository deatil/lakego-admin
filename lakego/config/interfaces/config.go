package interfaces

import (
    "time"
)

type Config interface {

    Clone(fileName string) Config

    Get(keyName string) interface{}

    GetString(keyName string) string

    GetBool(keyName string) bool

    GetInt(keyName string) int

    GetInt32(keyName string) int32

    GetInt64(keyName string) int64

    GetFloat64(keyName string) float64

    GetDuration(keyName string) time.Duration

    GetStringSlice(keyName string) []string

    GetStringMap(keyName string) map[string]interface{}

    GetStringMapString(keyName string) map[string]string
}
