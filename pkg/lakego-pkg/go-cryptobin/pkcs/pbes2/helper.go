package pbes2

// Cipher 列表
var cipherMap = map[string]Cipher{
    "DESCBC":      DESCBC,
    "DESEDE3CBC":  DESEDE3CBC,

    "RC2CBC":      RC2CBC,
    "RC2_40CBC":   RC2_40CBC,
    "RC2_64CBC":   RC2_64CBC,
    "RC2_128CBC":  RC2_128CBC,

    "RC5CBC":      RC5CBC,
    "RC5_128CBC":  RC5_128CBC,
    "RC5_192CBC":  RC5_192CBC,
    "RC5_256CBC":  RC5_256CBC,

    "AES128ECB":   AES128ECB,
    "AES128CBC":   AES128CBC,
    "AES128OFB":   AES128OFB,
    "AES128CFB":   AES128CFB,
    "AES128GCM":   AES128GCM,
    "AES128GCMIv": AES128GCMIv,
    "AES128CCM":   AES128CCM,
    "AES128CCMIv": AES128CCMIv,

    "AES192ECB":   AES192ECB,
    "AES192CBC":   AES192CBC,
    "AES192OFB":   AES192OFB,
    "AES192CFB":   AES192CFB,
    "AES192GCM":   AES192GCM,
    "AES192GCMIv": AES192GCMIv,
    "AES192CCM":   AES192CCM,
    "AES192CCMIv": AES192CCMIv,

    "AES256ECB":   AES256ECB,
    "AES256CBC":   AES256CBC,
    "AES256OFB":   AES256OFB,
    "AES256CFB":   AES256CFB,
    "AES256GCM":   AES256GCM,
    "AES256GCMIv": AES256GCMIv,
    "AES256CCM":   AES256CCM,
    "AES256CCMIv": AES256CCMIv,

    "SM4Cipher": SM4Cipher,
    "SM4ECB":    SM4ECB,
    "SM4CBC":    SM4CBC,
    "SM4OFB":    SM4OFB,
    "SM4CFB":    SM4CFB,
    "SM4CFB1":   SM4CFB1,
    "SM4CFB8":   SM4CFB8,
    "SM4GCM":    SM4GCM,
    "SM4GCMIv":  SM4GCMIv,
    "SM4CCM":    SM4CCM,
    "SM4CCMIv":  SM4CCMIv,

    "GostCipher": GostCipher,

    "ARIA128ECB": ARIA128ECB,
    "ARIA128CBC": ARIA128CBC,
    "ARIA128CFB": ARIA128CFB,
    "ARIA128OFB": ARIA128OFB,
    "ARIA128CTR": ARIA128CTR,
    "ARIA128GCM": ARIA128GCM,
    "ARIA128CCM": ARIA128CCM,

    "ARIA192ECB": ARIA192ECB,
    "ARIA192CBC": ARIA192CBC,
    "ARIA192CFB": ARIA192CFB,
    "ARIA192OFB": ARIA192OFB,
    "ARIA192CTR": ARIA192CTR,
    "ARIA192GCM": ARIA192GCM,
    "ARIA192CCM": ARIA192CCM,

    "ARIA256ECB": ARIA256ECB,
    "ARIA256CBC": ARIA256CBC,
    "ARIA256CFB": ARIA256CFB,
    "ARIA256OFB": ARIA256OFB,
    "ARIA256CTR": ARIA256CTR,
    "ARIA256GCM": ARIA256GCM,
    "ARIA256CCM": ARIA256CCM,

    "Misty1CBC": Misty1CBC,

    "Serpent128ECB": Serpent128ECB,
    "Serpent128CBC": Serpent128CBC,
    "Serpent128OFB": Serpent128OFB,
    "Serpent128CFB": Serpent128CFB,

    "Serpent192ECB": Serpent192ECB,
    "Serpent192CBC": Serpent192CBC,
    "Serpent192OFB": Serpent192OFB,
    "Serpent192CFB": Serpent192CFB,

    "Serpent256ECB": Serpent256ECB,
    "Serpent256CBC": Serpent256CBC,
    "Serpent256OFB": Serpent256OFB,
    "Serpent256CFB": Serpent256CFB,

    // seed
    "SeedECB": SeedECB,
    "SeedCBC": SeedCBC,
    "SeedOFB": SeedOFB,
    "SeedCFB": SeedCFB,

    "Seed256ECB": Seed256ECB,
    "Seed256CBC": Seed256CBC,
    "Seed256OFB": Seed256OFB,
    "Seed256CFB": Seed256CFB,
}

// 获取 Cipher 类型
func GetCipherFromName(name string) Cipher {
    if data, ok := cipherMap[name]; ok {
        return data
    }

    return cipherMap["AES256CBC"]
}

// 检测 Cipher 类型
func CheckCipherFromName(name string) bool {
    if _, ok := cipherMap[name]; ok {
        return true
    }

    return false
}

// 获取 Cipher 类型名称
func GetCipherName(c Cipher) string {
    for name, cipher := range cipherMap {
        if cipher.OID().Equal(c.OID()) {
            return name
        }
    }

    return ""
}

// 检测 Cipher
func CheckCipher(c Cipher) bool {
    for _, cipher := range cipherMap {
        if cipher.OID().Equal(c.OID()) {
            return true
        }
    }

    return false
}
