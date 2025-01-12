package pbes2

// hash map
var hashMap = map[string]Hash{
    "MD5":             MD5,
    "SHA1":            SHA1,
    "SHA224":          SHA224,
    "SHA256":          SHA256,
    "SHA384":          SHA384,
    "SHA512":          SHA512,
    "SHA512_224":      SHA512_224,
    "SHA512_256":      SHA512_256,
    "SM3":             SM3,
    "GOST34112012256": GOST34112012256,
    "GOST34112012512": GOST34112012512,
}

// Get Hash From hash Name
func GetHashFromName(name string) Hash {
    if data, ok := hashMap[name]; ok {
        return data
    }

    return hashMap["SHA1"]
}

// make options
func MakeOpts(opts ...any) (Opts, error) {
    if len(opts) == 0 {
        return DefaultOpts, nil
    }

    switch newOpt := opts[0].(type) {
        case Opts:
            return newOpt, nil
        case Cipher:
            cipher := newOpt

            kdfOpts := PBKDF2Opts{
                SaltSize:       16,
                IterationCount: 10000,
            }

            // hash
            if len(opts) > 1 {
                switch hash := opts[1].(type) {
                    case Hash:
                        kdfOpts.HMACHash = hash
                    case string:
                        kdfOpts.HMACHash = GetHashFromName(hash)
                }
            }

            // Opts
            newOpts := Opts{
                Cipher:  cipher,
                KDFOpts: kdfOpts,
            }

            return newOpts, nil
        case string:
            cipName := "AES256CBC"
            if len(opts) > 0 {
                cipName = opts[0].(string)
            }

            cipher := GetCipherFromName(cipName)

            kdfOpts := PBKDF2Opts{
                SaltSize:       16,
                IterationCount: 10000,
            }

            // hash
            if len(opts) > 1 {
                switch hash := opts[1].(type) {
                    case Hash:
                        kdfOpts.HMACHash = hash
                    case string:
                        kdfOpts.HMACHash = GetHashFromName(hash)
                }
            }

            // Opts
            newOpts := Opts{
                Cipher:  cipher,
                KDFOpts: kdfOpts,
            }

            return newOpts, nil
    }

    return DefaultOpts, nil
}

// parse and make options
func ParseOpts(opts ...any) (Opts, error) {
    return MakeOpts(opts...)
}
