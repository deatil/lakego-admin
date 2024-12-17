package utils

import (
    "crypto/rand"
)

// 随机生成字符
func GenRandom(n int) ([]byte, error) {
    value := make([]byte, n)
    _, err := rand.Read(value)
    return value, err
}
