package padding

import (
    "bytes"
    "errors"
)

/**
 * TBC 补码
 *
 * @create 2024-12-5
 * @author deatil
 */
type TBC struct {}

// 构造函数
func NewTBC() TBC {
    return TBC{}
}

// TBCPadding(Trailling-Bit-Compliment)
// 填充至符合块大小的整数倍，原文最后一位为1时填充0x00，最后一位为0时填充0xFF。
func (this TBC) Padding(text []byte, blockSize int) []byte {
    n := len(text)
    if n == 0 || blockSize < 1 {
        return text
    }

    // 补位 blockSize 值
    paddingSize := blockSize - n%blockSize

    lastBit := text[n - 1] & 0x1

    var paddingByte byte
    if lastBit != 0 {
        paddingByte = 0x00
    } else {
        paddingByte = 0xFF
    }

    paddingText := bytes.Repeat([]byte{paddingByte}, paddingSize)
    text = append(text, paddingText...)

    return text
}

func (this TBC) UnPadding(src []byte) ([]byte, error) {
    n := len(src)
    if n == 0 {
        return nil, errors.New("invalid data len")
    }

    lastByte := src[n-1]

    switch {
        case lastByte == 0x00:
            for i := n - 2; i >= 0; i-- {
                if src[i] != 0x00 {
                    return src[:i+1], nil
                }
            }
        case lastByte == 0xFF:
            for i := n - 2; i >= 0; i-- {
                if src[i] != 0xFF {
                    return src[:i+1], nil
                }
            }
    }

    return nil, errors.New("invalid padding")
}
