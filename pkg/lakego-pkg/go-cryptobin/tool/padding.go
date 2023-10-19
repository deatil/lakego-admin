package tool

import (
    "bytes"
    "errors"
    "math/rand"
)

/**
 * 补码
 *
 * @create 2022-4-17
 * @author deatil
 */
type Padding struct {}

// 构造函数
func NewPadding() Padding {
    return Padding{}
}

// 明文补码算法
// 填充至符合块大小的整数倍，填充值为填充数量数
func (this Padding) PKCS7Padding(text []byte, blockSize int) []byte {
    n := len(text)
    if n == 0 || blockSize < 1 {
        return text
    }

    // 补位 blockSize 值
    paddingSize := blockSize - n%blockSize
    paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)

    return append(text, paddingText...)
}

// 明文减码算法
func (this Padding) PKCS7UnPadding(src []byte) ([]byte, error) {
    n := len(src)
    if n == 0 {
        return nil, errors.New("invalid data len")
    }

    unpadding := int(src[n-1])

    num := n - unpadding
    if num < 0 {
        return nil, errors.New("invalid padding")
    }

    padding := src[num:]
    for i := 0; i < unpadding; i++ {
        if padding[i] != byte(unpadding) {
            return nil, errors.New("invalid padding")
        }
    }

    return src[:num], nil
}

// ==================

// PKCS7Padding的子集，块大小固定为8字节
func (this Padding) PKCS5Padding(text []byte) []byte {
    return this.PKCS7Padding(text, 8)
}

func (this Padding) PKCS5UnPadding(src []byte) ([]byte, error) {
    return this.PKCS7UnPadding(src)
}

// ==================

// 数据长度不对齐时使用0填充，否则不填充
func (this Padding) ZeroPadding(text []byte, blockSize int) []byte {
    n := len(text)
    if n == 0 || blockSize < 1 {
        return text
    }

    // 补位 blockSize 值
    paddingSize := blockSize - n%blockSize
    paddingText := bytes.Repeat([]byte{byte(0)}, paddingSize)

    return append(text, paddingText...)
}

func (this Padding) ZeroUnPadding(src []byte) ([]byte, error) {
    return bytes.TrimRight(src, string([]byte{0})), nil
}

// ==================

// ISO/IEC 9797-1 Padding Method 2
// 填充至符合块大小的整数倍，填充值第一个字节为0x80，其他字节填0x00。
func (this Padding) ISO97971Padding(text []byte, blockSize int) []byte {
    return this.ZeroPadding(append(text, 0x80), blockSize)
}

func (this Padding) ISO97971UnPadding(src []byte) ([]byte, error) {
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

// ==================

// PBOC2.0的MAC运算数据填充规范
// 若原加密数据的最末字节可能是0x80，则不推荐使用该模式
func (this Padding) PBOC2Padding(text []byte, blockSize int) []byte {
    return this.ISO97971Padding(text, blockSize)
}

func (this Padding) PBOC2UnPadding(src []byte) ([]byte, error) {
    return this.ISO97971UnPadding(src)
}

// ==================

// X923Padding
// 填充至符合块大小的整数倍，填充值最后一个字节为填充的数量数，其他字节填0
func (this Padding) X923Padding(text []byte, blockSize int) []byte {
    n := len(text)
    if n == 0 || blockSize < 1 {
        return text
    }

    // 补位 blockSize 值
    paddingSize := blockSize - n%blockSize
    paddingText := bytes.Repeat([]byte{byte(0)}, paddingSize - 1)

    text = append(text, paddingText...)
    text = append(text, byte(paddingSize))

    return text
}

func (this Padding) X923UnPadding(src []byte) ([]byte, error) {
    n := len(src)
    if n == 0 {
        return nil, errors.New("invalid data len")
    }

    unpadding := int(src[n-1])

    num := n - unpadding
    if num < 0 {
        return nil, errors.New("invalid padding")
    }

    padding := src[num:]
    for i := 0; i < unpadding - 1; i++ {
        if padding[i] != byte(0) {
            return nil, errors.New("invalid padding")
        }
    }

    return src[:num], nil
}

// ==================

// ISO10126Padding
// 填充至符合块大小的整数倍，填充值最后一个字节为填充的数量数，其他字节填充随机字节。
func (this Padding) ISO10126Padding(text []byte, blockSize int) []byte {
    n := len(text)
    if n == 0 || blockSize < 1 {
        return text
    }

    // 补位 blockSize 值
    paddingSize := blockSize - n%blockSize
    paddingText := this.RandomBytes(uint(paddingSize - 1))

    text = append(text, paddingText...)
    text = append(text, byte(paddingSize))

    return text
}

func (this Padding) ISO10126UnPadding(src []byte) ([]byte, error) {
    n := len(src)
    if n == 0 {
        return nil, errors.New("invalid data len")
    }

    num := n - int(src[n-1])
    if num < 0 {
        return nil, errors.New("invalid padding")
    }

    return src[:num], nil
}

// ==================

// ISO7816_4Padding
// 填充至符合块大小的整数倍，填充值第一个字节为0x80，其他字节填0x00。
func (this Padding) ISO7816_4Padding(text []byte, blockSize int) []byte {
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

func (this Padding) ISO7816_4UnPadding(src []byte) ([]byte, error) {
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

// ==================

// TBCPadding(Trailling-Bit-Compliment)
// 填充至符合块大小的整数倍，原文最后一位为1时填充0x00，最后一位为0时填充0xFF。
func (this Padding) TBCPadding(text []byte, blockSize int) []byte {
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

func (this Padding) TBCUnPadding(src []byte) ([]byte, error) {
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

// ==================

// 填充格式如下:
// Padding = 00 + BT + PS + 00 + D
// 00为固定字节
// BT为处理模式
// PS为填充字节，填充数量为 k - 3 - D ，k表示密钥长度, D表示原文长度。
// PS的最小长度为8个字节。填充的值根据BT值来定：
// BT = 00时，填充全0x00
// BT = 01时，填充全0xFF
// BT = 02时，随机填充，但不能为00。
func (this Padding) PKCS1Padding(text []byte, blockSize int, bt string) []byte {
    n := len(text)
    if n == 0 || blockSize < 1 {
        return text
    }

    paddingSize := blockSize - 3 - n
    if paddingSize < 8 {
        return text
    }

    // 00
    text = append(text, 0x00)

    switch {
        case bt == "00":
            // BT
            text = append(text, 0x00)

            // PS
            paddingText := bytes.Repeat([]byte{0x00}, paddingSize)
            text = append(text, paddingText...)
        case bt == "01":
            text = append(text, 0x01)

            paddingText := bytes.Repeat([]byte{0xFF}, paddingSize)
            text = append(text, paddingText...)
        case bt == "02":
            text = append(text, 0x02)

            paddingText := this.RandomBytes(uint(paddingSize))
            text = append(text, paddingText...)
    }

    // 00
    text = append(text, 0x00)

    // D
    text = append(text, byte(n))

    return text
}

func (this Padding) PKCS1UnPadding(src []byte) ([]byte, error) {
    n := len(src)
    if n == 0 {
        return nil, errors.New("invalid data len")
    }

    count := int(src[n-1])
    if count > n {
        return nil, errors.New("invalid padding")
    }

    return src[:count], nil
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
