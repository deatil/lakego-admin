package padding

import (
    "bytes"
    "errors"

    "github.com/deatil/go-cryptobin/tool/alias"
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
    overhead := blockSize - len(text)%blockSize
    ret, out := alias.SliceForAppend(text, overhead)

    out[0] = 0x80
    for i := 1; i < overhead; i++ {
        out[i] = 0
    }

    return ret
}

func (this ISO97971) UnPadding(src []byte) ([]byte, error) {
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
