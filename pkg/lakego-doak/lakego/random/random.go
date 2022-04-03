package random

import (
    "time"
    "strings"
    "math/rand"
)

// Charsets
const (
    Uppercase    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    Lowercase    = "abcdefghijklmnopqrstuvwxyz"
    Alphabetic   = Uppercase + Lowercase
    Numeric      = "0123456789"
    Alphanumeric = Alphabetic + Numeric
    Symbols      = "`" + `~!@#$%^&*()-_+={}[]|\;:"<>,./?`
    Hex          = Numeric + "abcdef"
)

// 随机数字符
func String(length uint8, charsets ...string) string {
    return New().String(length, charsets...)
}

func New() *Random {
    rand.Seed(time.Now().UnixNano())
    return new(Random)
}

/**
 * 随机数
 *
 * @create 2021-8-28
 * @author deatil
 */
type Random struct {}

func (*Random) String(length uint8, charsets ...string) string {
    charset := strings.Join(charsets, "")
    if charset == "" {
        charset = Alphanumeric
    }

    b := make([]byte, length)
    for i := range b {
        b[i] = charset[rand.Int63()%int64(len(charset))]
    }

    return string(b)
}
