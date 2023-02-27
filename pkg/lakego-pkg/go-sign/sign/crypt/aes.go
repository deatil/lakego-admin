package crypt

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
)

// Encrypt 加密 aes_128_cbc
func AesEncrypt(encryptStr string, key []byte, iv string) (string, error) {
    encryptBytes := []byte(encryptStr)
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    blockSize := block.BlockSize()
    encryptBytes = pkcs7Padding(encryptBytes, blockSize)

    blockMode := cipher.NewCBCEncrypter(block, []byte(iv))
    encrypted := make([]byte, len(encryptBytes))
    blockMode.CryptBlocks(encrypted, encryptBytes)
    return base64.URLEncoding.EncodeToString(encrypted), nil
}

// Decrypt 解密
func AesDecrypt(decryptStr string, key []byte, iv string) (string, error) {
    decryptBytes, err := base64.URLEncoding.DecodeString(decryptStr)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    blockMode := cipher.NewCBCDecrypter(block, []byte(iv))
    decrypted := make([]byte, len(decryptBytes))

    blockMode.CryptBlocks(decrypted, decryptBytes)
    decrypted = pkcs7UnPadding(decrypted)
    return string(decrypted), nil
}

func pkcs7Padding(cipherText []byte, blockSize int) []byte {
    padding := blockSize - len(cipherText)%blockSize
    padText := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(cipherText, padText...)
}

func pkcs7UnPadding(decrypted []byte) []byte {
    length := len(decrypted)
    unPadding := int(decrypted[length-1])
    return decrypted[:(length - unPadding)]
}
