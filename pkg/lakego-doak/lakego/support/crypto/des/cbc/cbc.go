package cbc

import (
    "fmt"
    "crypto/des"
    "crypto/cipher"
    "encoding/hex"

    "github.com/deatil/lakego-doak/lakego/support/crypto/des/tool"
)

var (
    // 默认向量
    defaultIv = "a91ebd0s"
)

// CBC 加密
func EncryptDES(src string, key string, ivStr string) (string, error) {
    data := []byte(src)
    keyByte := []byte(key)

    block, err := des.NewCipher(keyByte)
    if err != nil {
        return "", err
    }

    data = tool.PKCS5Padding(data, block.BlockSize())

    // 向量
    iv := []byte(ivStr)
    mode := cipher.NewCBCEncrypter(block, iv)

    out := make([]byte, len(data))
    mode.CryptBlocks(out, data)

    return fmt.Sprintf("%X", out), nil
}

// CBC 解密
func DecryptDES(src string, key string, ivStr string) (string, error) {
    keyByte := []byte(key)

    data, err := hex.DecodeString(src)
    if err != nil {
        return "", err
    }

    block, err := des.NewCipher(keyByte)
    if err != nil {
        return "", err
    }

    // 向量
    iv := []byte(ivStr)
    mode := cipher.NewCBCDecrypter(block, iv)
    plaintext := make([]byte, len(data))

    mode.CryptBlocks(plaintext, data)
    plaintext = tool.PKCS5UnPadding(plaintext)

    return string(plaintext), nil
}

// 加密 Encode("12fgt", "dfertf12")
func Encode(str string, key string, iv ...string) string {
    ivStr := defaultIv
    if len(iv) > 0 {
        ivStr = iv[0]
    }

    enstr, err := EncryptDES(str, key, ivStr)
    if err != nil {
        return ""
    }

    return enstr
}

// 解密 Decode("AF381D34F51CD48E", "dfertf12")
func Decode(str string, key string, iv ...string) string {
    ivStr := defaultIv
    if len(iv) > 0 {
        ivStr = iv[0]
    }

    destr, err := DecryptDES(str, key)
    if err != nil {
        return ""
    }

    return destr
}
