package base64

import (
	"encoding/base64"
)

// 加密
func Encode(str string) string {
	newStr := base64.StdEncoding.EncodeToString([]byte(str))
	return newStr
}

// 解密
func Decode(str string) string {
	var newStr []byte 
	var err error
	
	newStr, err = base64.StdEncoding.DecodeString(str)
	if err != nil {
		return ""
	}
	
	return string(newStr)
}
