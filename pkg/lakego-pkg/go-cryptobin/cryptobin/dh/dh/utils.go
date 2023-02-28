package dh

import(
    "math/rand"
)

var defaultLetters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// 生成随机字符
func RandomString(n int64, allowedChars ...[]rune) string {
    var letters []rune

    if len(allowedChars) == 0 {
        letters = defaultLetters
    } else {
        letters = allowedChars[0]
    }

    b := make([]rune, n)
    for i := range b {
        b[i] = letters[rand.Intn(len(letters))]
    }

    return string(b)
}
