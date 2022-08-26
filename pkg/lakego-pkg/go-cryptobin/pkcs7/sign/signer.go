package sign

import (
    "hash"
    "crypto"
)

// 通用加密
func hashSignData(hashType crypto.Hash, data []byte) []byte {
    h := hashType.New()
    h.Write(data)
    hash := h.Sum(nil)

    return hash
}

// 通用加密
func hashFuncSignData(hashType func() hash.Hash, data []byte) []byte {
    h := hashType()
    h.Write(data)
    hash := h.Sum(nil)

    return hash
}

