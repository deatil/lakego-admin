package ecb

import (
    "crypto/aes"
    "encoding/base64"
	"encoding/hex"
)

func AesEncryptECB(origData []byte, key []byte) (encrypted []byte) {
	cipher, _ := aes.NewCipher(generateKey(key))
	length := (len(origData) + aes.BlockSize) / aes.BlockSize
	plain := make([]byte, length*aes.BlockSize)
	copy(plain, origData)
	pad := byte(len(plain) - len(origData))
	for i := len(origData); i < len(plain); i++ {
		plain[i] = pad
	}
	
	encrypted = make([]byte, len(plain))
	
	// 分组分块加密
	for bs, be := 0, cipher.BlockSize(); bs <= len(origData); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Encrypt(encrypted[bs:be], plain[bs:be])
	}

	return encrypted
}

func AesDecryptECB(encrypted []byte, key []byte) (decrypted []byte) {
	cipher, _ := aes.NewCipher(generateKey(key))
	decrypted = make([]byte, len(encrypted))
	
	for bs, be := 0, cipher.BlockSize(); bs < len(encrypted); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Decrypt(decrypted[bs:be], encrypted[bs:be])
	}

	trim := 0
	if len(decrypted) > 0 {
		trim = len(decrypted) - int(decrypted[len(decrypted)-1])
	}

	return decrypted[:trim]
}

func generateKey(key []byte) (genKey []byte) {
	genKey = make([]byte, 16)
	copy(genKey, key)
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			genKey[j] ^= key[i]
		}
	}
	return genKey
}

// 加密
// Encode("rfgty", "dfertf12dfertf12")
func Encode(str string, key string) string {
    aeskey := []byte(key)
    newStr := []byte(str)
    enStr := AesEncryptECB(newStr, aeskey)
	
	return base64.StdEncoding.EncodeToString(enStr)
}

// 解密
// Decode("9sKOe+3NeiHG2cl65K9aNg==", "dfertf12dfertf12")
func Decode(str string, key string) string {
    base64Str, err := base64.StdEncoding.DecodeString(str)
    if err != nil {
        return ""
    }
	
    aeskey := []byte(key)
    deStr := AesDecryptECB(base64Str, aeskey)
	
	return string(deStr)
}

// Hex 加密
// HexEncode("rfgty", "dfertf12dfertf12")
func HexEncode(str string, key string) string {
    aeskey := []byte(key)
    newStr := []byte(str)
    enStr := AesEncryptECB(newStr, aeskey)
	
	return hex.EncodeToString(enStr)
}

// Hex 解密
// HexDecode("f6c28e7bedcd7a21c6d9c97ae4af5a36", "dfertf12dfertf12")
func HexDecode(str string, key string) string {
    base64Str, err := hex.DecodeString(str)
    if err != nil {
        return ""
    }
	
    aeskey := []byte(key)
    deStr := AesDecryptECB(base64Str, aeskey)
	
	return string(deStr)
}
