package jceks

import(
    "github.com/deatil/go-cryptobin/padding"
    "github.com/deatil/go-cryptobin/tool/utils"
)

var newPadding = padding.NewPKCS7()

// 明文补码算法
func pkcs7Padding(text []byte, blockSize int) []byte {
    return newPadding.Padding(text, blockSize)
}

// 明文减码算法
func pkcs7UnPadding(src []byte) ([]byte, error) {
    return newPadding.UnPadding(src)
}

// 随机生成字符
func genRandom(num int) ([]byte, error) {
    return utils.GenRandom(num)
}
