package hash

import (
    "errors"
    "crypto"
    _ "crypto/md5"
    _ "crypto/sha1"
    _ "crypto/sha256"
    _ "crypto/sha512"

    _ "golang.org/x/crypto/md4"
    _ "golang.org/x/crypto/sha3"
    _ "golang.org/x/crypto/blake2s"
    _ "golang.org/x/crypto/blake2b"
    _ "golang.org/x/crypto/ripemd160"
)

// hash 官方默认
var cryptoHashes = map[string]crypto.Hash{
    "MD4":         crypto.MD4,
    "MD5":         crypto.MD5,
    "SHA1":        crypto.SHA1,
    "SHA224":      crypto.SHA224,
    "SHA256":      crypto.SHA256,
    "SHA384":      crypto.SHA384,
    "SHA512":      crypto.SHA512,
    "RIPEMD160":   crypto.RIPEMD160,
    "SHA3_224":    crypto.SHA3_224,
    "SHA3_256":    crypto.SHA3_256,
    "SHA3_384":    crypto.SHA3_384,
    "SHA3_512":    crypto.SHA3_512,
    "SHA512_224":  crypto.SHA512_224,
    "SHA512_256":  crypto.SHA512_256,
    "BLAKE2s_256": crypto.BLAKE2s_256,
    "BLAKE2b_256": crypto.BLAKE2b_256,
    "BLAKE2b_384": crypto.BLAKE2b_384,
    "BLAKE2b_512": crypto.BLAKE2b_512,
}

// 类型
func GetCryptoHash(typ string) (crypto.Hash, error) {
    h, ok := cryptoHashes[typ]
    if ok {
        return h, nil
    }

    return 0, errors.New("hash type is not support")
}

// 签名后数据
func CryptoHashSum(typ string, slices ...[]byte) ([]byte, error) {
    hasher, err := GetCryptoHash(typ)
    if err != nil {
        return nil, err
    }

    h := hasher.New()
    for _, slice := range slices {
        h.Write(slice)
    }

    return h.Sum(nil), nil
}
