package pkcs8

// Cipher 列表
var CipherMap = map[string]Cipher{
    "DESCBC":     DESCBC,
    "DESEDE3CBC": DESEDE3CBC,

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
    "SM4CFB8":    SM4CFB8,
    "SM4GCM":     SM4GCM,
    "SM4GCMb":    SM4GCMb,
    "SM4CCM":     SM4CCM,
    "SM4CCMb":    SM4CCMb,
}

// hash 列表
var HashMap = map[string]Hash{
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

    return HashMap["SHA1"]
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

            kdfOpts := PBKDF2Opts{
                SaltSize:       16,
                IterationCount: 10000,
            }

            // MD5 | SHA1 | SHA224 | SHA256 | SHA384
            // SHA512 | SHA512_224 | SHA512_256 | SM3
            if len(opts) > 1 {
                hash := opts[1].(string)

                kdfOpts.HMACHash = GetHashFromName(hash)
            }

            cipher := GetCipherFromName(opt)

            // 设置
            newOpts := Opts{
                Cipher:  cipher,
                KDFOpts: kdfOpts,
            }

            return newOpts, nil
    }

    return DefaultOpts, nil
}
