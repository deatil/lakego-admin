package padding

import (
    "bytes"
    "errors"
)

/**
 * PBOC2 补码
 *
 * @create 2024-12-5
 * @author deatil
 */
type PBOC2 struct {}

// 构造函数
func NewPBOC2() PBOC2 {
    return PBOC2{}
}

// PBOC2.0的MAC运算数据填充规范
// 若原加密数据的最末字节可能是0x80，则不推荐使用该模式
// 与 ISO97971Padding 一致
func (this PBOC2) Padding(text []byte, blockSize int) []byte {
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

func (this PBOC2) UnPadding(src []byte) ([]byte, error) {
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
