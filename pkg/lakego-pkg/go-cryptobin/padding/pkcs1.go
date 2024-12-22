package padding

import (
    "bytes"
    "errors"
)

/**
 * PKCS1 补码
 *
 * @create 2024-12-5
 * @author deatil
 */
type PKCS1 struct {
    bt string
}

// 构造函数
func NewPKCS1(bt string) PKCS1 {
    return PKCS1{
        bt: bt,
    }
}

// 填充格式如下:
// Padding = 00 + BT + PS + 00 + D
// 00为固定字节
// BT为处理模式
// PS为填充字节，填充数量为 k - 3 - D ，k表示密钥长度, D表示原文长度。
// PS的最小长度为8个字节。填充的值根据BT值来定：
// BT = 00时，填充全0x00
// BT = 01时，填充全0xFF
// BT = 02时，随机填充，但不能为00。
func (this PKCS1) Padding(text []byte, blockSize int) []byte {
    n := len(text)
    if blockSize < 1 {
        return text
    }

    paddingSize := blockSize - 3 - n
    if paddingSize < 8 {
        return text
    }

    bt := this.bt

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

            paddingText := randomBytes(uint(paddingSize))
            text = append(text, paddingText...)
    }

    // 00
    text = append(text, 0x00)

    // D
    text = append(text, byte(n))

    return text
}

func (this PKCS1) UnPadding(src []byte) ([]byte, error) {
    n := len(src)
    if n == 0 {
        return nil, errors.New("invalid data length")
    }

    count := int(src[n-1])
    if count > n {
        return nil, errors.New("invalid padding")
    }

    return src[:count], nil
}
