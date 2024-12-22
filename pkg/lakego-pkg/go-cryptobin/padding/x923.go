package padding

import (
    "bytes"
    "errors"
)

/**
 * X923 补码
 *
 * @create 2024-12-5
 * @author deatil
 */
type X923 struct {}

// 构造函数
// ansiX923
// https://www.ibm.com/docs/en/linux-on-systems?topic=processes-ansi-x923-cipher-block-chaining
func NewX923() X923 {
    return X923{}
}

// X923Padding / ansiX923Padding
// 填充至符合块大小的整数倍，填充值最后一个字节为填充的数量数，其他字节填0
func (this X923) Padding(text []byte, blockSize int) []byte {
    num := len(text)
    if blockSize < 1 {
        return text
    }

    overhead := blockSize - num%blockSize
    paddingText := bytes.Repeat([]byte{0}, overhead)

    text = append(text, paddingText...)
    text[len(text)-1] = byte(overhead)

    return text
}

func (this X923) UnPadding(src []byte) ([]byte, error) {
    n := len(src)
    if n == 0 {
        return nil, errors.New("invalid data length")
    }

    unpadding := int(src[n-1])

    num := n - unpadding
    if num < 0 {
        return nil, errors.New("invalid padding length")
    }

    padding := src[num:]
    for i := 0; i < unpadding - 1; i++ {
        if padding[i] != byte(0) {
            return nil, errors.New("invalid padding bytes")
        }
    }

    return src[:num], nil
}
