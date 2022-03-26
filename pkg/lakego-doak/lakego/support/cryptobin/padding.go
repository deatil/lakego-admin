package cryptobin

import (
    "bytes"
)

// 明文补码算法
func (this Crypto) Pkcs7Padding(text []byte, blockSize int) []byte {
    paddingSize := blockSize - len(text)%blockSize
    paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)

    return append(text, paddingText...)
}

// 明文减码算法
func (this Crypto) Pkcs7UnPadding(src []byte) []byte {
    n := len(src)
    if n == 0 {
        return src
    }

    count := int(src[n-1])
    text := src[:n-count]
    return text
}

// PKCS7Padding的子集，块大小固定为8字节
func (this Crypto) Pkcs5Padding(text []byte)[]byte  {
    return this.Pkcs7Padding(text, 8)
}

func (this Crypto) Pkcs5UnPadding(src []byte)[]byte  {
    return this.Pkcs7UnPadding(src)
}

// 数据长度不对齐时使用0填充，否则不填充
func (this Crypto) ZerosPadding(text []byte, blockSize int) []byte{
    paddingSize := blockSize - len(text)%blockSize
    paddingText := bytes.Repeat([]byte{byte(0)}, paddingSize)
    return append(text, paddingText...)
}

func (this Crypto) ZerosUnPadding(src []byte)[]byte  {
    return bytes.TrimRight(src,string([]byte{0}))
}
