package cbc

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "encoding/hex"
)

var (
    // 默认向量
    defaultIv = "a91ebd0s"
)

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
    padding := blockSize - len(ciphertext)%blockSize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
    length := len(origData)
    unpadding := int(origData[length-1])
    return origData[:(length - unpadding)]
}

func AesEncryptCBC(src string, key string, ivStr string) ([]byte, error) {
    data := []byte(src)
    keyByte := []byte(key)

    block, err := aes.NewCipher(keyByte)
    if err != nil {
        return nil, err
    }

    // 向量
    iv := []byte(ivStr)

    blockMode := cipher.NewCBCEncrypter(block, iv)

    data = PKCS5Padding(data, block.BlockSize())
    crypted := make([]byte, len(data))
    blockMode.CryptBlocks(crypted, data)

    return crypted, nil
}

func AesDecryptCBC(src string, key string, ivStr string) ([]byte, error) {
    data := []byte(src)
    keyByte := []byte(key)

    block, err := aes.NewCipher(keyByte)
    if err != nil {
        return nil, err
    }

    // 向量
    iv := []byte(ivStr)

    blockMode := cipher.NewCBCDecrypter(block, iv)

    origData := make([]byte, len(data))
    blockMode.CryptBlocks(origData, data)

    origData = PKCS5UnPadding(origData)

    return origData, nil
}

// 加密
// Encode("fgtre", "dfertf12dfertf12")
/*
16 字节 - AES-128
24 字节 - AES-192
32 字节 - AES-256
*/
func Encode(str string, key string, iv ...string) string {
    ivStr := defaultIv
    if len(iv) > 0 {
        ivStr = iv[0]
    }

    enStr, err := AesEncryptCBC(str, key, ivStr)
    if err != nil {
        return err.Error()
    }

    return base64.StdEncoding.EncodeToString(enStr)
}

// 解密
// Decode("UGFrxUqdF4drEh3Wsf7bng==", "dfertf12dfertf12")
func Decode(str string, key string, iv ...string) string {
    ivStr := defaultIv
    if len(iv) > 0 {
        ivStr = iv[0]
    }

    base64Str, err := base64.StdEncoding.DecodeString(str)
    if err != nil {
        return ""
    }

    deStr, err := AesDecryptCBC(string(base64Str), key, ivStr)
    if err != nil {
        return ""
    }

    return string(deStr)
}

// Hex 加密
// HexEncode("fgtre", "dfertf12dfertf12")
func HexEncode(str string, key string, iv ...string) string {
    ivStr := defaultIv
    if len(iv) > 0 {
        ivStr = iv[0]
    }

    enStr, err := AesEncryptCBC(str, key, ivStr)
    if err != nil {
        return ""
    }

    return hex.EncodeToString(enStr)
}

// Hex 解密
// HexDecode("50616bc54a9d17876b121dd6b1fedb9e", "dfertf12dfertf12")
func HexDecode(str string, key string, iv ...string) string {
    ivStr := defaultIv
    if len(iv) > 0 {
        ivStr = iv[0]
    }

    base64Str, err := hex.DecodeString(str)
    if err != nil {
        return ""
    }

    deStr, err := AesDecryptCBC(string(base64Str), key, ivStr)
    if err != nil {
        return ""
    }

    return string(deStr)
}
