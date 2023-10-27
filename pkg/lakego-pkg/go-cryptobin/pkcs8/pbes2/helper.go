package pbes2

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

// 需要设置 KeyLength 的 Cipher
func IsUseKeyLengthCipher(cipher Cipher) bool {
    switch cipher.OID().String() {
        case RC2CBC.OID().String(), RC2_40CBC.OID().String(),
            RC2_64CBC.OID().String(), RC2_128CBC.OID().String(),
            RC5CBC.OID().String(), RC5_128CBC.OID().String(),
            RC5_192CBC.OID().String(), RC5_256CBC.OID().String():
            return true
        default:
            return false
    }
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
            cipher := newOpt

            var kdfOpts KDFOpts

            if IsUseKeyLengthCipher(cipher) {
                kdfOpts = PBKDF2OptsWithKeyLength{
                    SaltSize:       16,
                    IterationCount: 10000,
                }
            } else {
                kdfOpts = PBKDF2Opts{
                    SaltSize:       16,
                    IterationCount: 10000,
                }
            }

            // 设置
            newOpts := Opts{
                Cipher:  cipher,
                KDFOpts: kdfOpts,
            }

            return newOpts, nil
        case string:
            opt := "AES256CBC"
            if len(opts) > 0 {
                opt = opts[0].(string)
            }

            cipher := GetCipherFromName(opt)

            var newOpts Opts

            if IsUseKeyLengthCipher(cipher) {
                kdfOpts := PBKDF2OptsWithKeyLength{
                    SaltSize:       16,
                    IterationCount: 10000,
                }

                // hash
                if len(opts) > 1 {
                    hash := opts[1].(string)

                    kdfOpts.HMACHash = GetHashFromName(hash)
                }

                // 设置
                newOpts = Opts{
                    Cipher:  cipher,
                    KDFOpts: kdfOpts,
                }
            } else {
                kdfOpts := PBKDF2Opts{
                    SaltSize:       16,
                    IterationCount: 10000,
                }

                // hash
                if len(opts) > 1 {
                    hash := opts[1].(string)

                    kdfOpts.HMACHash = GetHashFromName(hash)
                }

                // 设置
                newOpts = Opts{
                    Cipher:  cipher,
                    KDFOpts: kdfOpts,
                }
            }

            return newOpts, nil
    }

    return DefaultOpts, nil
}
