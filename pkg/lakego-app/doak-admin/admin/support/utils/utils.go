package utils

import (
    "github.com/deatil/go-hash/hash"
)

func MD5(data string) string {
    return hash.FromString(data).MD5().ToHexString()
}
