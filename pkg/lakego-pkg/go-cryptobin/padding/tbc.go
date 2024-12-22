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
    if blockSize < 1 {
        return text
    }

    // 补位 blockSize 值
    paddingSize := blockSize - n%blockSize

    var paddingByte byte
    if n > 0 {
        lastBit := text[n - 1] & 0x1

        if lastBit != 0 {
            paddingByte = 0x00
        } else {
            paddingByte = 0xFF
        }
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
        return nil, errors.New("invalid data length")
    }

    res := []byte{}

    lastByte := src[n-1]

    switch lastByte {
        case 0x00:
            for i := n - 2; i >= 0; i-- {
                if src[i] != 0x00 {
                    res = src[:i+1]
                    break
                }
            }

            if len(res) > 0 {
                lastBit := res[len(res) - 1] & 0x1
                if lastBit == 0 {
                    return nil, errors.New("invalid padding")
                }
            } else {
                return nil, errors.New("invalid padding")
            }
        case 0xFF:
            for i := n - 2; i >= 0; i-- {
                if src[i] != 0xFF {
                    res = src[:i+1]
                    break
                }
            }

            if len(res) > 0 {
                lastBit := res[len(res) - 1] & 0x1
                if lastBit != 0 {
                    return nil, errors.New("invalid padding")
                }
            }
        default:
            return nil, errors.New("invalid padding")
    }

    return res, nil
}
