package padding

import (
    "bytes"
)

/**
 * Zero 补码
 *
 * @create 2024-12-5
 * @author deatil
 */
type Zero struct {}

// 构造函数
func NewZero() Zero {
    return Zero{}
}

// 数据长度不对齐时使用0填充，否则不填充
func (this Zero) Padding(text []byte, blockSize int) []byte {
    n := len(text)
    if n == 0 || blockSize < 1 {
        return text
    }

    // 补位 blockSize 值
    paddingSize := blockSize - n%blockSize
    paddingText := bytes.Repeat([]byte{byte(0)}, paddingSize)

    return append(text, paddingText...)
}

func (this Zero) UnPadding(src []byte) ([]byte, error) {
    return bytes.TrimRight(src, string([]byte{0})), nil
}
