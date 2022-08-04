package pkcs8

// Cipher 列表
var CipherMap = map[string]Cipher{
    "DESCBC":     DESCBC,
    "DESEDE3CBC": DESEDE3CBC,

    "AES128CBC":  AES128CBC,
    "AES192CBC":  AES192CBC,
    "AES256CBC":  AES256CBC,

    "AES128GCM":  AES128GCM,
    "AES192GCM":  AES192GCM,
    "AES256GCM":  AES256GCM,

    "SM4CBC":     SM4CBC,
    "SM4GCM":     SM4GCM,
}

// hash 列表
var HashMap = map[string]Hash{
    "MD4":        MD4,
    "MD5":        MD5,
    "SHA1":       SHA1,
    "SHA224":     SHA224,
    "SHA256":     SHA256,
    "SHA384":     SHA384,
    "SHA512":     SHA512,
    "SHA512_224": SHA512_224,
    "SHA512_256": SHA512_256,
    "SM3":        SM3,
}

// 获取 Cipher 类型
func GetCipherFromName(name string) Cipher {
    if data, ok := CipherMap[name]; ok {
        return data
    }

    return CipherMap["AES256CBC"]
}

// 获取 hash 类型
func GetHashFromName(name string) Hash {
    if data, ok := HashMap[name]; ok {
        return data
    }

    return HashMap["SHA256"]
}

// 解析配置
func ParseOpts(opts ...any) (Opts, error) {
    if len(opts) == 0 {
        return DefaultOpts, nil
    }

    switch newOpt := opts[0].(type) {
        case Opts:
            return newOpt, nil
        case string:
            // DESCBC | DESEDE3CBC
            // AES128CBC | AES192CBC | AES256CBC
            // AES128GCM | AES192GCM | AES256GCM
            // SM4CBC | SM4GCM
            opt := "AES256CBC"
            if len(opts) > 0 {
                opt = opts[0].(string)
            }

            // MD4 | MD5 | SHA1 | SHA224 | SHA256 | SHA384
            // SHA512 | SHA512_224 | SHA512_256 | SM3
            hash := "SHA256"
            if len(opts) > 1 {
                hash = opts[1].(string)
            }

            cipher := GetCipherFromName(opt)
            hmacHash := GetHashFromName(hash)

            // 设置
            newOpts := Opts{
                Cipher:  cipher,
                KDFOpts: PBKDF2Opts{
                    SaltSize:       16,
                    IterationCount: 10000,
                    HMACHash:       hmacHash,
                },
            }

            return newOpts, nil
    }

    return DefaultOpts, nil
}
