package pkcs12

import(
    "bytes"
    "crypto/rand"
)

// 随机生成字符
func genRandom(len int) ([]byte, error) {
    value := make([]byte, len)
    _, err := rand.Read(value)
    return value, err
}

// 明文补码算法
// 填充至符合块大小的整数倍，填充值为填充数量数
func pkcs7Padding(text []byte, blockSize int) []byte {
    n := len(text)
    if n == 0 || blockSize < 1 {
        return text
    }

    paddingSize := blockSize - n%blockSize

    // 为 0 时补位 blockSize 值
    if paddingSize == 0 {
        paddingSize = blockSize
    }

    paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)

    return append(text, paddingText...)
}

// 明文减码算法
func pkcs7UnPadding(src []byte) []byte {
    n := len(src)
    if n == 0 {
        return src
    }

    count := int(src[n-1])

    num := n-count
    if num < 0 {
        return src
    }

    text := src[:num]
    return text
}
