package ecb

import (
	"fmt"
	"errors"
	"crypto/des"
	"encoding/hex"
		
	"lakego-admin/lakego/support/des/tool"
)

func EncryptDES(src string, key string) (string, error) {
    data := []byte(src)
    keyByte := []byte(key)
    block, err := des.NewCipher(keyByte)
    if err != nil {
        return "", err
    }
	
    bs := block.BlockSize()
	
    // 对明文数据进行补码
    data = tool.PKCS5Padding(data, bs)
    if len(data)%bs != 0 {
        return "", errors.New("size error")
    }
	
    out := make([]byte, len(data))
    dst := out
    for len(data) > 0 {
        // 对明文按照blocksize进行分块加密
        // 必要时可以使用go关键字进行并行加密
        block.Encrypt(dst, data[:bs])
        data = data[bs:]
        dst = dst[bs:]
    }
	
    return fmt.Sprintf("%X", out), nil
}
 
// ECB解密
func DecryptDES(src string, key string) (string, error) {
    data, err := hex.DecodeString(src)
    if err != nil {
        return "", err
    }
    keyByte := []byte(key)
    block, err := des.NewCipher(keyByte)
    if err != nil {
        return "", err
    }
	
    bs := block.BlockSize()
    if len(data)%bs != 0 {
        return "", errors.New("size error")
    }
	
    out := make([]byte, len(data))
    dst := out
    for len(data) > 0 {
        block.Decrypt(dst, data[:bs])
        data = data[bs:]
        dst = dst[bs:]
    }
    out = tool.PKCS5UnPadding(out)
    return string(out), nil
}


// 加密 Encode("asert", "dfertf12")
func Encode(str string, key string) string {
    enstr, err := EncryptDES(str, key)
    if err != nil {
        return ""
    }
	
	return enstr
}

// 解密 Decode("950F58725B70C79E", "dfertf12")
func Decode(str string, key string) string {
    destr, err := DecryptDES(str, key)
    if err != nil {
        return ""
    }
	
	return destr
}

