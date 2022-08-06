package pkcs8pbe

// PEMCipher 列表
var PEMCipherMap = map[string]PEMCipher{
    "MD5AndDES":      PEMCipherMD5AndDES,
    "SHA1AndDES":     PEMCipherSHA1AndDES,
    "SHA1And3DES":    PEMCipherSHA1And3DES,
    "SHA1AndRC4_128": PEMCipherSHA1AndRC4_128,
    "SHA1AndRC4_40":  PEMCipherSHA1AndRC4_40,
}

// 获取 Cipher 类型
func GetCipherFromName(name string) PEMCipher {
    if data, ok := PEMCipherMap[name]; ok {
        return data
    }

    return PEMCipherMap["MD5AndDES"]
}

// 获取 Cipher 类型
func CheckCipherFromName(name string) bool {
    if _, ok := PEMCipherMap[name]; ok {
        return true
    }

    return false
}
