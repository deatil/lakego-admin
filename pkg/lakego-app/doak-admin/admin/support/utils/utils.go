package utils

import (
    "github.com/deatil/go-hash/hash"

    "github.com/deatil/lakego-doak/lakego/array"
    "github.com/deatil/lakego-doak/lakego/constraints"
)

func MD5(data string) string {
    return hash.FromString(data).MD5().ToHexString()
}

func SHA256(data string) string {
    return hash.FromString(data).SHA256().ToHexString()
}

func FormatAccess[T constraints.Ordered](olds, news []T) (adds, deletes []T) {
    adds = array.ArrayDiff(olds, news)
    deletes = array.ArrayDiff(news, olds)

    return
}
