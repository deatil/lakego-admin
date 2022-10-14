package jceks

import (
    "fmt"
    "hash"
    "bytes"

    "golang.org/x/text/encoding/unicode"
    "golang.org/x/text/transform"

    "github.com/deatil/go-cryptobin/kdf/pbkdf"
)

func formatPassword(password []byte) []byte {
    // Convert password to byte array, so that it can be digested.
    passwdBytes := make([]byte, len(password))
    for i := 0; i < len(password); i++ {
        passwdBytes[i] = password[i] & 0x7f
    }

    return passwdBytes
}

func formatSalt(salt []byte) ([]byte, error) {
    if len(salt) != 8 {
        return nil, fmt.Errorf("unexpected salt length: %d", len(salt))
    }

    if bytes.Compare(salt[0:4], salt[4:]) == 0 {
        // First and second half of salt are equal, invert first half.
        for i := 0; i < 2; i++ {
            salt[i], salt[3-i] = salt[3-i], salt[i]
        }
    }

    return salt, nil
}

// 迭代生成密钥
// keyLen = 24
// ivLen = 8
func derivedKey(
    password string,
    salt string,
    iter int,
    keyLen int,
    ivLen int,
    h func() hash.Hash,
) ([]byte, []byte) {
    passwdBytes := formatPassword([]byte(password))

    saltBytes, err := formatSalt([]byte(salt))
    if err != nil {
        return nil, nil
    }

    derivedKey := make([]byte, keyLen+ivLen)

    md := h()
    for i := 0; i < 2; i++ {
        n := len(saltBytes) / 2
        toBeHashed := saltBytes[i*n : (i+1)*n]
        for j := 0; j < iter; j++ {
            md.Write(toBeHashed)
            md.Write(passwdBytes)
            toBeHashed = md.Sum([]byte{})
            md.Reset()
        }

        copy(derivedKey[i*len(toBeHashed):], toBeHashed)
    }

    cipherKey := derivedKey[:keyLen]
    iv := derivedKey[keyLen:]

    return cipherKey, iv
}

func bksFormatPassword(password []byte) []byte {
    if len(password) == 0 {
        return password
    }

    passwordUTF16BE, _, _ := transform.Bytes(unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM).NewEncoder(), password)
    passwordUTF16BE = append(passwordUTF16BE, []byte{0x00, 0x00}...)

    return passwordUTF16BE
}

// 生成密钥
func derivedKeyWithPbkdf(
    password string,
    salt string,
    iter int,
    keyLen int,
    ivLen int,
    h func() hash.Hash,
) ([]byte, []byte) {
    passwdBytes := bksFormatPassword([]byte(password))
    saltBytes := []byte(salt)

    key := pbkdf.Key(h, 20, 64, saltBytes, passwdBytes, iter, 1, keyLen)
    iv := pbkdf.Key(h, 20, 64, saltBytes, passwdBytes, iter, 2, ivLen)

    return key, iv
}

// 生成密钥
func derivedHmacKey(
    password string,
    salt string,
    iter int,
    keyLen int,
    h func() hash.Hash,
) []byte {
    passwdBytes := bksFormatPassword([]byte(password))
    saltBytes := []byte(salt)

    hmacKey := pbkdf.Key(h, 20, 64, saltBytes, passwdBytes, iter, 3, keyLen)

    return hmacKey
}
