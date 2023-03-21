package encrypt

import(
    "github.com/deatil/go-cryptobin/tool"
)

var newPadding = tool.NewPadding()

// 明文补码算法
func pkcs7Padding(text []byte, blockSize int) []byte {
    return newPadding.PKCS7Padding(text, blockSize)
}

// 明文减码算法
func pkcs7UnPadding(src []byte) []byte {
    return newPadding.PKCS7UnPadding(src)
}

// 随机生成字符
func genRandom(num int) ([]byte, error) {
    return tool.GenRandom(num)
}
