package cbc

import (
    "fmt"
    "crypto/des"
    "crypto/cipher"
    "encoding/hex"

    "github.com/deatil/lakego-doak/lakego/support/crypto/des/tool"
)

// CBC 加密
func EncryptDES(src string, key string) (string, error) {
    data := []byte(src)
    keyByte := []byte(key)
    block, err := des.NewCipher(keyByte)
    if err != nil {
        return "", err
    }

    data = tool.PKCS5Padding(data, block.BlockSize())

    // 向量
    iv := []byte("a91ebd0s")
    mode := cipher.NewCBCEncrypter(block, iv)

    out := make([]byte, len(data))
    mode.CryptBlocks(out, data)

    return fmt.Sprintf("%X", out), nil
}

// CBC 解密
func DecryptDES(src string, key string) (string, error) {
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
    iv := []byte("a91ebd0s")
    mode := cipher.NewCBCDecrypter(block, iv)
    plaintext := make([]byte, len(data))

    mode.CryptBlocks(plaintext, data)
    plaintext = tool.PKCS5UnPadding(plaintext)

    return string(plaintext), nil
}

// 加密 Encode("12fgt", "dfertf12")
func Encode(str string, key string) string {
    enstr, err := EncryptDES(str, key)
    if err != nil {
        return ""
    }

    return enstr
}

// 解密 Decode("AF381D34F51CD48E", "dfertf12")
func Decode(str string, key string) string {
    destr, err := DecryptDES(str, key)
    if err != nil {
        return ""
    }

    return destr
}
