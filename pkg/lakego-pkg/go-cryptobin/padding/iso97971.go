package padding

import (
    "bytes"
    "errors"
)

/**
 * ISO97971 补码
 *
 * @create 2024-12-5
 * @author deatil
 */
type ISO97971 struct {}

// 构造函数
func NewISO97971() ISO97971 {
    return ISO97971{}
}

// ISO/IEC 9797-1 Padding Method 2
// 填充至符合块大小的整数倍，填充值第一个字节为0x80，其他字节填0x00。
func (this ISO97971) Padding(text []byte, blockSize int) []byte {
    num := len(text)
    if blockSize < 1 {
        return text
    }

    overhead := blockSize - num%blockSize
    paddingText := bytes.Repeat([]byte{0}, overhead)

    text = append(text, paddingText...)
    text[num] = 0x80

    return text
}

func (this ISO97971) UnPadding(src []byte) ([]byte, error) {
    n := len(src)
    if n == 0 {
        return nil, errors.New("invalid data length")
    }

    num := bytes.LastIndexByte(src, 0x80)
    if num == -1 {
        return nil, errors.New("invalid padding")
    }

    padding := src[num:]
    for i := 1; i < n - num; i++ {
        if padding[i] != byte(0) {
            return nil, errors.New("invalid padding")
        }
    }

    return src[:num], nil
}
