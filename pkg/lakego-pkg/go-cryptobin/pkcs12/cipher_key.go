package pkcs12

import (
    "hash"

    "github.com/deatil/go-cryptobin/kdf/pbkdf"
)

// 生成密钥
func derivedKey(password string, salt string, iter int, keyLen int, ivLen int, h func() hash.Hash) ([]byte, []byte) {
    key := pbkdf.Key(h, 20, 64, []byte(salt), []byte(password), iter, 1, keyLen)
    iv := pbkdf.Key(h, 20, 64, []byte(salt), []byte(password), iter, 2, ivLen)

    return key, iv
}
