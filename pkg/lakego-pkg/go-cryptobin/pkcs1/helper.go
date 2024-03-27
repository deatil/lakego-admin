package pkcs1

// Cipher 列表
var pemCiphers = map[string]Cipher{
    "DESCBC":         CipherDESCBC,
    "DESEDE3CBC":     Cipher3DESCBC,
    "AES128CBC":      CipherAES128CBC,
    "AES192CBC":      CipherAES192CBC,
    "AES256CBC":      CipherAES256CBC,
    "SM4CBC":         CipherSM4CBC,
    "GrasshopperCBC": CipherGrasshopperCBC,

    "DESCFB":         CipherDESCFB,
    "DESEDE3CFB":     Cipher3DESCFB,
    "AES128CFB":      CipherAES128CFB,
    "AES192CFB":      CipherAES192CFB,
    "AES256CFB":      CipherAES256CFB,
    "SM4CFB":         CipherSM4CFB,
    "GrasshopperCFB": CipherGrasshopperCFB,

    "DESOFB":         CipherDESOFB,
    "DESEDE3OFB":     Cipher3DESOFB,
    "AES128OFB":      CipherAES128OFB,
    "AES192OFB":      CipherAES192OFB,
    "AES256OFB":      CipherAES256OFB,
    "SM4OFB":         CipherSM4OFB,
    "GrasshopperOFB": CipherGrasshopperOFB,

    "DESCTR":         CipherDESCTR,
    "DESEDE3CTR":     Cipher3DESCTR,
    "AES128CTR":      CipherAES128CTR,
    "AES192CTR":      CipherAES192CTR,
    "AES256CTR":      CipherAES256CTR,
    "SM4CTR":         CipherSM4CTR,
    "GrasshopperCTR": CipherGrasshopperCTR,
}

// 获取 Cipher 类型
func GetPEMCipher(name string) Cipher {
    if cipher, ok := pemCiphers[name]; ok {
        return cipher
    }

    return nil
}

// 检测 Cipher 类型
func CheckPEMCipher(name string) bool {
    if _, ok := pemCiphers[name]; ok {
        return true
    }

    return false
}
