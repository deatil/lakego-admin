package ssh

import (
    "crypto/rand"
)

// 随机生成字符
func genRandom(len int) ([]byte, error) {
    value := make([]byte, len)
    _, err := rand.Read(value)
    return value, err
}
