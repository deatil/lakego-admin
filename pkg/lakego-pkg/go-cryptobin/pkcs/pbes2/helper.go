package pbes2

// Cipher 列表
var CipherMap = map[string]Cipher{
    "DESCBC":     DESCBC,
    "DESEDE3CBC": DESEDE3CBC,

    "RC2CBC":     RC2CBC,
    "RC2_40CBC":  RC2_40CBC,
    "RC2_64CBC":  RC2_64CBC,
    "RC2_128CBC": RC2_128CBC,

    "RC5CBC":     RC5CBC,
    "RC5_128CBC": RC5_128CBC,
    "RC5_192CBC": RC5_192CBC,
    "RC5_256CBC": RC5_256CBC,

    "AES128ECB":  AES128ECB,
    "AES128CBC":  AES128CBC,
    "AES128OFB":  AES128OFB,
    "AES128CFB":  AES128CFB,
    "AES128GCM":  AES128GCM,
    "AES128GCMb": AES128GCMb,
    "AES128CCM":  AES128CCM,
    "AES128CCMb": AES128CCMb,

    "AES192ECB":  AES192ECB,
    "AES192CBC":  AES192CBC,
    "AES192OFB":  AES192OFB,
    "AES192CFB":  AES192CFB,
    "AES192GCM":  AES192GCM,
    "AES192GCMb": AES192GCMb,
    "AES192CCM":  AES192CCM,
    "AES192CCMb": AES192CCMb,

    "AES256ECB":  AES256ECB,
    "AES256CBC":  AES256CBC,
    "AES256OFB":  AES256OFB,
    "AES256CFB":  AES256CFB,
    "AES256GCM":  AES256GCM,
    "AES256GCMb": AES256GCMb,
    "AES256CCM":  AES256CCM,
    "AES256CCMb": AES256CCMb,

    "SM4ECB":     SM4ECB,
    "SM4CBC":     SM4CBC,
    "SM4OFB":     SM4OFB,
    "SM4CFB":     SM4CFB,
    "SM4CFB1":    SM4CFB1,
    "SM4CFB8":    SM4CFB8,
    "SM4GCM":     SM4GCM,
    "SM4GCMb":    SM4GCMb,
    "SM4CCM":     SM4CCM,
    "SM4CCMb":    SM4CCMb,
}

// 获取 Cipher 类型
func GetCipherFromName(name string) Cipher {
    if data, ok := CipherMap[name]; ok {
        return data
    }

    return CipherMap["AES256CBC"]
}

// 检测 Cipher 类型
func CheckCipherFromName(name string) bool {
    if _, ok := CipherMap[name]; ok {
        return true
    }

    return false
}
