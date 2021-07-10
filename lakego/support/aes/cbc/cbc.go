package cbc

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "encoding/hex"
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

func AesEncryptCBC(origData, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    blockSize := block.BlockSize()
    origData = PKCS5Padding(origData, blockSize)
    blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
    crypted := make([]byte, len(origData))
    blockMode.CryptBlocks(crypted, origData)
    return crypted, nil
}

func AesDecryptCBC(crypted, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    blockSize := block.BlockSize()
    blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
    origData := make([]byte, len(crypted))
    blockMode.CryptBlocks(origData, crypted)
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
func Encode(str string, key string) string {
    aeskey := []byte(key)
    newStr := []byte(str)
    enStr, err := AesEncryptCBC(newStr, aeskey)
    if err != nil {
        return err.Error()
    }
    
    return base64.StdEncoding.EncodeToString(enStr)
}

// 解密 
// Decode("UGFrxUqdF4drEh3Wsf7bng==", "dfertf12dfertf12")
func Decode(str string, key string) string {
    base64Str, err := base64.StdEncoding.DecodeString(str)
    if err != nil {
        return ""
    }
    
    aeskey := []byte(key)
    deStr, err := AesDecryptCBC(base64Str, aeskey)
    if err != nil {
        return ""
    }
    
    return string(deStr)
}

// Hex 加密
// HexEncode("fgtre", "dfertf12dfertf12")
func HexEncode(str string, key string) string {
    aeskey := []byte(key)
    newStr := []byte(str)
    enStr, err := AesEncryptCBC(newStr, aeskey)
    if err != nil {
        return ""
    }
    
    return hex.EncodeToString(enStr)
}

// Hex 解密
// HexDecode("50616bc54a9d17876b121dd6b1fedb9e", "dfertf12dfertf12")
func HexDecode(str string, key string) string {
    base64Str, err := hex.DecodeString(str)
    if err != nil {
        return ""
    }
    
    aeskey := []byte(key)
    deStr, err := AesDecryptCBC(base64Str, aeskey)
    if err != nil {
        return ""
    }
    
    return string(deStr)
}
