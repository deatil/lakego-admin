package utils

import (
    "unsafe"
    "crypto/rand"
)

// 随机生成字符
func GenRandom(n int) ([]byte, error) {
    value := make([]byte, n)
    _, err := rand.Read(value)
    return value, err
}

// 根据指定长度分割字节
func BytesSplit(buf []byte, size int) [][]byte {
    var chunk []byte

    chunks := make([][]byte, 0, len(buf)/size+1)

    for len(buf) >= size {
        chunk, buf = buf[:size], buf[size:]
        chunks = append(chunks, chunk)
    }

    if len(buf) > 0 {
        chunks = append(chunks, buf[:])
    }

    return chunks
}

// 字符串转换为字节
func StringToBytes(str string) []byte {
    return *(*[]byte)(unsafe.Pointer(
        &struct {
            string
            Cap int
        }{str, len(str)},
    ))
}

// 字节转换为字符串
func BytesToString(buf []byte) string {
    return *(*string)(unsafe.Pointer(&buf))
}
