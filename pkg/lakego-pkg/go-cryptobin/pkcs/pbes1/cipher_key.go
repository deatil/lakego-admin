package pbes1

import (
    "hash"

    "github.com/deatil/go-cryptobin/kdf/pbkdf"
)

// 生成密钥
func derivedKey(password string, salt string, iter int, keyLen int, ivLen int, h func() hash.Hash) ([]byte, []byte) {
    key := hashKey(h, []byte(password + salt))

    for i := 0; i < iter - 1; i++ {
        key = hashKey(h, key)
    }

    return key[:keyLen], key[keyLen:keyLen+ivLen]
}

// 单个加密
func hashKey(h func() hash.Hash, key []byte) []byte {
    fn := h()
    fn.Write(key)

    return fn.Sum(nil)
}

// Pbkdf 生成密钥
func derivedKeyWithPbkdf(password string, salt string, iter int, keyLen int, ivLen int, h func() hash.Hash) ([]byte, []byte) {
    key := pbkdf.Key(h, 20, 64, []byte(salt), []byte(password), iter, 1, keyLen)
    iv := pbkdf.Key(h, 20, 64, []byte(salt), []byte(password), iter, 2, ivLen)

    return key, iv
}
