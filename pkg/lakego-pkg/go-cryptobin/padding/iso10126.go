package padding

import (
    "errors"
)

/**
 * ISO10126 补码
 *
 * @create 2024-12-5
 * @author deatil
 */
type ISO10126 struct {}

// 构造函数
func NewISO10126() ISO10126 {
    return ISO10126{}
}

// ISO10126Padding
// 填充至符合块大小的整数倍，填充值最后一个字节为填充的数量数，其他字节填充随机字节。
func (this ISO10126) Padding(text []byte, blockSize int) []byte {
    n := len(text)
    if blockSize < 1 {
        return text
    }

    // 补位 blockSize 值
    paddingSize := blockSize - n%blockSize
    paddingText := randomBytes(uint(paddingSize - 1))

    text = append(text, paddingText...)
    text = append(text, byte(paddingSize))

    return text
}

func (this ISO10126) UnPadding(src []byte) ([]byte, error) {
    n := len(src)
    if n == 0 {
        return nil, errors.New("invalid data length")
    }

    num := n - int(src[n-1])
    if num < 0 {
        return nil, errors.New("invalid padding")
    }

    return src[:num], nil
}
