package padding

import (
    "bytes"
    "errors"
)

/**
 * PKCS5 补码
 *
 * @create 2024-12-5
 * @author deatil
 */
type PKCS5 struct {}

// 构造函数
func NewPKCS5() PKCS5 {
    return PKCS5{}
}

// 明文补码算法
// 填充至符合块大小的整数倍，填充值为填充数量数
func (this PKCS5) Padding(text []byte, _ int) []byte {
    blockSize := 8

    n := len(text)
    if n == 0 || blockSize < 1 {
        return text
    }

    // 补位 blockSize 值
    paddingSize := blockSize - n%blockSize
    paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)

    return append(text, paddingText...)
}

// 明文减码算法
func (this PKCS5) UnPadding(src []byte) ([]byte, error) {
    n := len(src)
    if n == 0 {
        return nil, errors.New("invalid data len")
    }

    unpadding := int(src[n-1])

    num := n - unpadding
    if num < 0 {
        return nil, errors.New("invalid padding")
    }

    padding := src[num:]
    for i := 0; i < unpadding; i++ {
        if padding[i] != byte(unpadding) {
            return nil, errors.New("invalid padding")
        }
    }

    return src[:num], nil
}
