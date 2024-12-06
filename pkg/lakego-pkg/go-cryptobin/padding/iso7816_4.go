package padding

import (
    "bytes"
    "errors"
)

/**
 * ISO7816_4 补码
 *
 * @create 2024-12-5
 * @author deatil
 */
type ISO7816_4 struct {}

// 构造函数
func NewISO7816_4() ISO7816_4 {
    return ISO7816_4{}
}

// ISO7816_4Padding
// 填充至符合块大小的整数倍，填充值第一个字节为0x80，其他字节填0x00。
func (this ISO7816_4) Padding(text []byte, blockSize int) []byte {
    n := len(text)
    if n == 0 || blockSize < 1 {
        return text
    }

    // 补位 blockSize 值
    paddingSize := blockSize - n%blockSize

    text = append(text, 0x80)

    paddingText := bytes.Repeat([]byte{0x00}, paddingSize - 1)
    text = append(text, paddingText...)

    return text
}

func (this ISO7816_4) UnPadding(src []byte) ([]byte, error) {
    n := len(src)
    if n == 0 {
        return nil, errors.New("invalid data len")
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
