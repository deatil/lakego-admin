package pkcs8pbe

import (
    "hash"
)

// 单个加密
func hashKey(h func() hash.Hash, key []byte) []byte {
    fn := h()
    fn.Write(key)
    data := fn.Sum(nil)

    return data
}

// 生成密钥
func derivedKey(password string, salt string, iter int, keyLen int, h func() hash.Hash) ([]byte, []byte) {
    key := hashKey(h, []byte(password + salt))

    for i := 0; i < iter - 1; i++ {
        key = hashKey(h, key)
    }

    return key[:keyLen], key[keyLen:]
}

// 生成密钥2
func derivedKey2(password string, salt string, iter int, keyLen int, h func() hash.Hash) ([]byte, []byte) {
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
    iv := derived[1][8:]

    return key[:keyLen], iv
}

// 生成密钥3
func derivedKey3(password string, salt string, iter int, keyLen int, h func() hash.Hash) ([]byte, []byte) {
    key := hashKey(h, []byte(password + salt))

    for i := 0; i < iter - 1; i++ {
        key = hashKey(h, key)
    }

    newKey := append(key[:8], key[:8]...)
    newKey = append(newKey, key[:8]...)

    return newKey, key[8:]
}
