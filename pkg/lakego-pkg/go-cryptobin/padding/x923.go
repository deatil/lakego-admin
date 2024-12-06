package padding

import (
    "errors"

    "github.com/deatil/go-cryptobin/tool/alias"
)

/**
 * X923 补码
 *
 * @create 2024-12-5
 * @author deatil
 */
type X923 struct {}

// 构造函数
// https://www.ibm.com/docs/en/linux-on-systems?topic=processes-ansi-x923-cipher-block-chaining
func NewX923() X923 {
    return X923{}
}

// X923Padding / ansiX923Padding
// 填充至符合块大小的整数倍，填充值最后一个字节为填充的数量数，其他字节填0
func (this X923) Padding(text []byte, blockSize int) []byte {
    overhead := blockSize - len(text)%blockSize
    ret, out := alias.SliceForAppend(text, overhead)

    out[overhead-1] = byte(overhead)
    for i := 0; i < overhead-1; i++ {
        out[i] = 0
    }

    return ret
}

func (this X923) UnPadding(src []byte) ([]byte, error) {
    n := len(src)
    if n == 0 {
        return nil, errors.New("invalid data len")
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
