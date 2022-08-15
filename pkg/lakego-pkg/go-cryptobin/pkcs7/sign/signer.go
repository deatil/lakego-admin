package sign

import (
    "crypto"
)

// 通用加密
func hashSignData(hashType crypto.Hash, data []byte) []byte {
    h := hashType.New()
    h.Write(data)
    hash := h.Sum(nil)

    return hash
}

