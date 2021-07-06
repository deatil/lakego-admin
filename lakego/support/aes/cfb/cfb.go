package cfb

import (
	"io"
	"errors"
    "crypto/aes"
    "crypto/cipher"
	"crypto/rand"
    "encoding/base64"
	"encoding/hex"
)

func AesEncryptCFB(origData []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte(""), err
	}
	
	encrypted := make([]byte, aes.BlockSize+len(origData))
	iv := encrypted[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return []byte(""), err
	}
	
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encrypted[aes.BlockSize:], origData)
	
	return encrypted, nil
}

func AesDecryptCFB(encrypted []byte, key []byte) ([]byte, error) {
	block, _ := aes.NewCipher(key)
	if len(encrypted) < aes.BlockSize {
		return []byte(""), errors.New("ciphertext too short")
	}
	
	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(encrypted, encrypted)
	
	return encrypted, nil
}

// 加密
// Encode("fgtre", "dfertf12dfertf12")
func Encode(str string, key string) string {
    aeskey := []byte(key)
    newStr := []byte(str)
    enStr, err := AesEncryptCFB(newStr, aeskey)
    if err != nil {
        return ""
    }
	
	return base64.StdEncoding.EncodeToString(enStr)
}

// 解密
// Decode("KO2b81bONyjY5Y5U4p1wO1Hf7OHU", "dfertf12dfertf12")
func Decode(str string, key string) string {
    base64Str, err := base64.StdEncoding.DecodeString(str)
    if err != nil {
        return ""
    }
	
    aeskey := []byte(key)
    deStr, err := AesDecryptCFB(base64Str, aeskey)
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
    enStr, err := AesEncryptCFB(newStr, aeskey)
    if err != nil {
        return ""
    }
	
	return hex.EncodeToString(enStr)
}

// Hex 解密
// HexDecode("cf03953cc3376c1b57b4d35caadef0612fbda209c7", "dfertf12dfertf12")
func HexDecode(str string, key string) string {
    base64Str, err := hex.DecodeString(str)
    if err != nil {
        return ""
    }
	
    aeskey := []byte(key)
    deStr, err := AesDecryptCFB(base64Str, aeskey)
    if err != nil {
        return ""
    }
	
	return string(deStr)
}
