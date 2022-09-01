package ssh

// Cipher 列表
var CipherMap = map[string]Cipher{
    "AES128CTR": AES128CTR,
    "AES192CTR": AES192CTR,
    "AES256CTR": AES256CTR,

    "AES128CBC": AES128CBC,
    "AES192CBC": AES192CBC,
    "AES256CBC": AES256CBC,
}

// 获取 Cipher 类型
func GetCipherFromName(name string) Cipher {
    if data, ok := CipherMap[name]; ok {
        return data
    }

    return CipherMap["AES256CTR"]
}
