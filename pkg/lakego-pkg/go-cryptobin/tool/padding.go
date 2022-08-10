package tool

import (
    "bytes"
    "math/rand"
)

/**
 * 补码
 *
 * @create 2022-4-17
 * @author deatil
 */
type Padding struct {}

// 明文补码算法
// 填充至符合块大小的整数倍，填充值为填充数量数
func (this Padding) PKCS7Padding(text []byte, blockSize int) []byte {
    n := len(text)
    if n == 0 || blockSize < 1 {
        return text
    }

    paddingSize := blockSize - n%blockSize

    // 为 0 时补位 blockSize 值
    if paddingSize == 0 {
        paddingSize = blockSize
    }

    paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)

    return append(text, paddingText...)
}

// 明文减码算法
func (this Padding) PKCS7UnPadding(src []byte) []byte {
    n := len(src)
    if n == 0 {
        return src
    }

    count := int(src[n-1])

    num := n-count
    if num < 0 {
        return src
    }

    text := src[:num]
    return text
}

// ==================

// PKCS7Padding的子集，块大小固定为8字节
func (this Padding) PKCS5Padding(text []byte) []byte {
    return this.PKCS7Padding(text, 8)
}

func (this Padding) PKCS5UnPadding(src []byte) []byte {
    return this.PKCS7UnPadding(src)
}

// ==================

// 数据长度不对齐时使用0填充，否则不填充
func (this Padding) ZeroPadding(text []byte, blockSize int) []byte {
    n := len(text)
    if n == 0 || blockSize < 1 {
        return text
    }

    paddingSize := blockSize - n%blockSize

    // 为 0 时补位 blockSize 值
    if paddingSize == 0 {
        paddingSize = blockSize
    }

    paddingText := bytes.Repeat([]byte{byte(0)}, paddingSize)

    return append(text, paddingText...)
}

func (this Padding) ZeroUnPadding(src []byte) []byte {
    return bytes.TrimRight(src, string([]byte{0}))
}

// ==================

// ISO/IEC 9797-1 Padding Method 2
func (this Padding) ISO97971Padding(text []byte, blockSize int) []byte {
    return this.ZeroPadding(append(text, 0x80), blockSize)
}

func (this Padding) ISO97971UnPadding(src []byte) []byte {
    data := this.ZeroUnPadding(src)

    return data[:len(data)-1]
}

// ==================

// X923Padding
// 填充至符合块大小的整数倍，填充值最后一个字节为填充的数量数，其他字节填0
func (this Padding) X923Padding(text []byte, blockSize int) []byte {
    n := len(text)
    if n == 0 || blockSize < 1 {
        return text
    }

    paddingSize := blockSize - n%blockSize

    // 为 0 时补位 blockSize 值
    if paddingSize == 0 {
        paddingSize = blockSize
    }

    paddingText := bytes.Repeat([]byte{byte(0)}, paddingSize - 1)
    text = append(text, paddingText...)

    text = append(text, byte(paddingSize))

    return text
}

func (this Padding) X923UnPadding(src []byte) []byte {
    n := len(src)
    if n == 0 {
        return src
    }

    count := int(src[n-1])

    num := n-count
    if num < 0 {
        return src
    }

    text := src[:num]
    return text
}

// ==================

// ISO10126Padding
// 填充至符合块大小的整数倍，填充值最后一个字节为填充的数量数，其他字节填充随机字节。
func (this Padding) ISO10126Padding(text []byte, blockSize int) []byte {
    n := len(text)
    if n == 0 || blockSize < 1 {
        return text
    }

    paddingSize := blockSize - n%blockSize

    // 为 0 时补位 blockSize 值
    if paddingSize == 0 {
        paddingSize = blockSize
    }

    for i := 0; i < paddingSize - 1; i++ {
        text = append(text, this.RandomBytes(1)...)
    }

    text = append(text, byte(paddingSize))

    return text
}

func (this Padding) ISO10126UnPadding(src []byte) []byte {
    n := len(src)
    if n == 0 {
        return src
    }

    count := int(src[n-1])

    num := n-count
    if num < 0 {
        return src
    }

    text := src[:num]
    return text
}

// ==================

// ISO7816_4Padding
// 填充至符合块大小的整数倍，填充值第一个字节为0x80，其他字节填0x00。
func (this Padding) ISO7816_4Padding(text []byte, blockSize int) []byte {
    n := len(text)
    if n == 0 || blockSize < 1 {
        return text
    }

    paddingSize := blockSize - n%blockSize

    // 为 0 时补位 blockSize 值
    if paddingSize == 0 {
        paddingSize = blockSize
    }

    text = append(text, 0x80)

    paddingText := bytes.Repeat([]byte{0x00}, paddingSize - 1)
    text = append(text, paddingText...)

    return text
}

func (this Padding) ISO7816_4UnPadding(src []byte) []byte {
    n := len(src)
    if n == 0 {
        return src
    }

    count := bytes.LastIndexByte(src, 0x80)
    if count == -1 {
        return src
    }

    return src[:count]
}

// ==================

// TBCPadding(Trailling-Bit-Compliment)
// 填充至符合块大小的整数倍，原文最后一位为1时填充0x00，最后一位为0时填充0xFF。
func (this Padding) TBCPadding(text []byte, blockSize int) []byte {
    n := len(text)
    if n == 0 || blockSize < 1 {
        return text
    }

    paddingSize := blockSize - n%blockSize

    // 为 0 时补位 blockSize 值
    if paddingSize == 0 {
        paddingSize = blockSize
    }

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

func (this Padding) TBCUnPadding(src []byte) []byte {
    n := len(src)
    if n == 0 {
        return src
    }

    lastByte := src[n-1]

    switch {
        case lastByte == 0x00:
            for i := n - 2; i >= 0; i-- {
                if src[i] != 0x00 {
                    return src[:i+1]
                }
            }
        case lastByte == 0xFF:
            for i := n - 2; i >= 0; i-- {
                if src[i] != 0xFF {
                    return src[:i+1]
                }
            }
    }

    return src
}

// ==================

// 填充格式如下:
// Padding = 00 + BT + PS + 00 + D
// 00为固定字节
// BT为处理模式
// PS为填充字节，填充数量为k - 3 - D，k表示密钥长度, D表示原文长度。
// PS的最小长度为8个字节。填充的值根据BT值来定：
// BT = 00时，填充全00
// BT = 01时，填充全FF
// BT = 02时，随机填充，但不能为00。
func (this Padding) PKCS1Padding(text []byte, blockSize int, bt string) []byte {
    n := len(text)
    if n == 0 || blockSize < 1 {
        return text
    }

    paddingSize := blockSize - 3 - n

    if paddingSize < 1 {
        return text
    }

    // 00
    text = append(text, 0x00)

    switch {
        case bt == "00":
            // BT
            text = append(text, 0x00)

            // PS
            for i := 1; i <= paddingSize; i++ {
                text = append(text, 0x00)
            }
        case bt == "01":
            text = append(text, 0x01)

            for i := 1; i <= paddingSize; i++ {
                text = append(text, 0xFF)
            }
        case bt == "02":
            text = append(text, 0x02)

            for i := 1; i <= paddingSize; i++ {
                text = append(text, this.RandomBytes(1)...)
            }
    }

    // 00
    text = append(text, 0x00)

    // D
    text = append(text, byte(n))

    return text
}

func (this Padding) PKCS1UnPadding(src []byte) []byte {
    n := len(src)
    if n == 0 {
        return src
    }

    count := int(src[n-1])
    return src[:count]
}

// ==================

// 随机字节
func (this Padding) RandomBytes(length uint) []byte {
    charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"

    b := make([]byte, length)
    for i := range b {
        b[i] = charset[rand.Int63()%int64(len(charset))]
    }

    return b
}

// 构造函数
func NewPadding() Padding {
    return Padding{}
}
