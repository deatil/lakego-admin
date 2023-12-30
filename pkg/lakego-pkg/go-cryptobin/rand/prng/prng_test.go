package prng

import (
    "testing"
    "crypto/aes"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/rand/keygen"
)

func Test_Crypto(t *testing.T) {
    str := []byte("test123")
    key := []byte("123456")

    // 加密
    res, err := AesEncryptECB(str, key)
    if err != nil {
        t.Fatal(err)
    }

    check := "668c826342b8703d86e8bbf404610499"
    if hex.EncodeToString(res) != check {
        t.Error("en error")
    }

    // 解密
    de, err := AesDecryptECB(res, key)
    if err != nil {
        t.Fatal(err)
    }

    if string(str) != string(de) {
        t.Error("de error")
    }

}

// content：test123
// encryptKey：123456
// 加密结果为：668C826342B8703D86E8BBF404610499
// 此时就和 java 结果相对应了，解密也一样对 key 加一步处理就行
func AesEncryptECB(src []byte, key []byte) ([]byte, error) {
    pr := SHA1PRNG.SetSeed(key)

    key, err := keygen.New(128, pr).GenerateKey()
    if err != nil {
        return nil, err
    }

    cipher, _ := aes.NewCipher(key)
    length := (len(src) + aes.BlockSize) / aes.BlockSize
    plain := make([]byte, length*aes.BlockSize)

    copy(plain, src)
    pad := byte(len(plain) - len(src))
    for i := len(src); i < len(plain); i++ {
        plain[i] = pad
    }

    encrypted := make([]byte, len(plain))
    // 分组分块加密
    for bs, be := 0, cipher.BlockSize(); bs <= len(src); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
        cipher.Encrypt(encrypted[bs:be], plain[bs:be])
    }

    return encrypted, nil
}

func AesDecryptECB(encrypted []byte, key []byte) ([]byte, error) {
    pr := SHA1PRNG.SetSeed(key)

    key, err := keygen.New(128, pr).GenerateKey()
    if err != nil {
        return nil, err
    }

    if err != nil {
        return nil, err
    }

    cipher, _ := aes.NewCipher(key)
    decrypted := make([]byte, len(encrypted))
    //
    for bs, be := 0, cipher.BlockSize(); bs < len(encrypted); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
        cipher.Decrypt(decrypted[bs:be], encrypted[bs:be])
    }

    trim := 0
    if len(decrypted) > 0 {
        trim = len(decrypted) - int(decrypted[len(decrypted)-1])
    }

    return decrypted[:trim], nil
}
