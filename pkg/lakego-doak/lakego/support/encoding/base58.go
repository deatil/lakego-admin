package encoding

import (
    "bytes"
    "math/big"
)

// 数据
var base58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

// Base58 编码
func Base58Encode(str string) string {
    input := []byte(str)

    var result []byte

    x := big.NewInt(0).SetBytes(input)

    base := big.NewInt(int64(len(base58Alphabet)))
    zero := big.NewInt(0)

    mod := &big.Int{}

    for x.Cmp(zero) != 0 {
        x, mod = x.DivMod(x, base, mod) //DIVMod,x除以base，返回商和余数
        result = append(result, base58Alphabet[mod.Int64()])//余数去对应字母表
    }

    if input[0] == 0x00 {
        result = append(result, base58Alphabet[0])
    }

    ReverseBytes(result)

    return string(result)
}

// Base58 解码
func Base58Decode(str string) string {
    input := []byte(str)

    result := big.NewInt(0)

    for _, b := range input {
        charIndex := bytes.IndexByte(base58Alphabet, b)
        result.Mul(result, big.NewInt(58))
        result.Add(result, big.NewInt(int64(charIndex)))
    }

    decoded := result.Bytes()

    if input[0] == base58Alphabet[0] {
        decoded = append([]byte{0x00}, decoded...)
    }

    return string(decoded)
}

// 翻转字节
func ReverseBytes(data []byte) {
    for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
        data[i], data[j] = data[j], data[i]
    }
}
