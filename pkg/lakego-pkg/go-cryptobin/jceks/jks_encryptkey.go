package jceks

import (
    "errors"
    "crypto/sha1"
    "crypto/subtle"
)

// 解密密钥
func jksDecryptKey(encryptedPKI []byte, passwd []byte) ([]byte, error) {
    encr, err := DecryptedPrivateKeyInfo(encryptedPKI)
    if err != nil {
        return nil, err
    }

    keystream := encr[:20]
    check := encr[len(encr)-20:]

    passwd = charsToBytes(passwd)

    key := make([]byte, len(encr)-40)

    sha := sha1.New()

    count := 0
    for count < len(key) {
        sha.Reset()
        sha.Write(passwd)
        sha.Write(keystream)

        toBeHashed := sha.Sum(nil)
        keystream = toBeHashed[:len(keystream)]
        for i := 0; i < len(keystream) && count < len(key); i++ {
            key[count] = keystream[i] ^ encr[count+20]
            count++
        }
    }

    sha.Reset()
    sha.Write(passwd)
    sha.Write(key)

    if subtle.ConstantTimeCompare(check, sha.Sum(nil)) != 1 {
        return nil, errors.New("keystore was tampered with or password was incorrect")
    }

    return key, nil
}

// 加密密钥
func jksEncryptKey(key []byte, passwd []byte) ([]byte, error) {
    encrypted := make([]byte, len(key) + 40)
    keystream, err := genRandom(20)
    if err != nil {
        return nil, err
    }

    copy(encrypted[:20], keystream)

    passwd = charsToBytes(passwd)

    sha := sha1.New()

    count := 0
    for count < len(key) {
        sha.Reset()
        sha.Write(passwd)
        sha.Write(keystream)

        toBeHashed := sha.Sum(nil)
        keystream = toBeHashed[:len(keystream)]
        for i := 0; i < len(keystream) && count < len(key); i++ {
            encrypted[count+20] = keystream[i] ^ key[count]
            count++
        }
    }

    sha.Reset()
    sha.Write(passwd)
    sha.Write(key)

    copy(encrypted[len(encrypted)-20:], sha.Sum(nil))

    return EncryptedPrivateKeyInfo(oidKeyProtector, encrypted)
}
