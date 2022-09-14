package pkcs8pbe

import (
    "hash"

    "github.com/deatil/go-cryptobin/kdf/pbkdf"
)

// 单个加密
func hashKey(h func() hash.Hash, key []byte) []byte {
    fn := h()
    fn.Write(key)
    data := fn.Sum(nil)

    return data
}

// 生成密钥
func derivedKey(password string, salt string, iter int, keyLen int, ivLen int, h func() hash.Hash) ([]byte, []byte) {
    key := hashKey(h, []byte(password + salt))

    for i := 0; i < iter - 1; i++ {
        key = hashKey(h, key)
    }

    return key[:keyLen], key[keyLen:keyLen+ivLen]
}

// 生成密钥2
func derivedKeyWithHalves(password string, salt string, iter int, keyLen int, ivLen int, h func() hash.Hash) ([]byte, []byte) {
    newPassword := []byte(password)
    newSalt := []byte(salt)

    saltHalves := [][]byte{newSalt[:4], newSalt[4:]}

    var derived [2][]byte
    for i := 0; i < 2; i++ {
        derived[i] = saltHalves[i]

        for j := 0; j < iter; j++ {
            r := hashKey(h, append(derived[i], newPassword...))

            derived[i] = r[:]
        }
    }

    key := append(derived[0][:], derived[1][:]...)
    iv := derived[1][8:8+ivLen]

    return key[:keyLen], iv
}

// 生成密钥
func derivedKeyWithPbkdf(password string, salt string, iter int, keyLen int, ivLen int, h func() hash.Hash) ([]byte, []byte) {
    key := pbkdf.Key(h, 20, 64, []byte(salt), []byte(password), iter, 1, keyLen)
    iv := pbkdf.Key(h, 20, 64, []byte(salt), []byte(password), iter, 2, ivLen)

    return key, iv
}
