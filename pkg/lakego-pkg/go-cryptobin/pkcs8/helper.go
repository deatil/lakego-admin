package pkcs8

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
        case Cipher:
            kdfOpts := PBKDF2Opts{
                SaltSize:       16,
                IterationCount: 10000,
            }

            cipher := newOpt

            // 设置
            newOpts := Opts{
                Cipher:  cipher,
                KDFOpts: kdfOpts,
            }

            return newOpts, nil
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
