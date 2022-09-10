package pkcs8pbe

// PEMCipher 列表
var PEMCipherMap = map[string]PEMCipher{
    "MD2AndDES":      PEMCipherMD2AndDES,
    "MD5AndDES":      PEMCipherMD5AndDES,
    "SHA1AndDES":     PEMCipherSHA1AndDES,
    "SHA1And3DES":    PEMCipherSHA1And3DES,
    "SHA1AndRC4_128": PEMCipherSHA1AndRC4_128,
    "SHA1AndRC4_40":  PEMCipherSHA1AndRC4_40,

    "SHA1AndRC2_128": PEMCipherSHA1AndRC2_128,
    "SHA1AndRC2_40":  PEMCipherSHA1AndRC2_40,
    "SHA1AndRC2_64":  PEMCipherSHA1AndRC2_64,
    "MD2AndRC2_64":   PEMCipherMD2AndRC2_64,
    "MD5AndRC2_64":   PEMCipherMD5AndRC2_64,
}

// 获取 Cipher 类型
func GetCipherFromName(name string) PEMCipher {
    if data, ok := PEMCipherMap[name]; ok {
        return data
    }

    return PEMCipherMap["MD5AndDES"]
}

// 检测 Cipher 类型
func CheckCipherFromName(name string) bool {
    if _, ok := PEMCipherMap[name]; ok {
        return true
    }

    return false
}
