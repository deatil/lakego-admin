package padding

import (
    "math/rand"
)

// padding interface struct
type Padding interface {
    // Padding func
    Padding(text []byte, blockSize int) []byte

    // UnPadding func
    UnPadding(src []byte) ([]byte, error)
}

// 随机字节
func randomBytes(length uint) []byte {
    charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"

    b := make([]byte, length)
    for i := range b {
        b[i] = charset[rand.Int63()%int64(len(charset))]
    }

    return b
}
