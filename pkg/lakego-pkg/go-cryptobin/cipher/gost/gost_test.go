package gost

import (
    "fmt"
    "bytes"
    "testing"
    "math/rand"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/tool"
)

func Test_Gosts(t *testing.T) {
    test_Gost(t, DESDerivedSbox, "DESDerivedSbox")
    test_Gost(t, TestSbox, "TestSbox")
    test_Gost(t, CryptoProSbox, "CryptoProSbox")
    test_Gost(t, SboxIdtc26gost28147paramZ, "SboxIdtc26gost28147paramZ")
}

func test_Gost(t *testing.T, sbox [][]byte, name string) {
    t.Run(name, func(t *testing.T) {
        random := rand.New(rand.NewSource(99))
        max := 5000

        var encrypted [8]byte
        var decrypted [8]byte

        for i := 0; i < max; i++ {
            key := make([]byte, 32)
            random.Read(key)
            value := make([]byte, 8)
            random.Read(value)

            cipher1, err := NewCipher(key, sbox)
            if err != nil {
                t.Fatal(err.Error())
            }

            cipher1.Encrypt(encrypted[:], value)

            cipher2, err := NewCipher(key, sbox)
            if err != nil {
                t.Fatal(err.Error())
            }

            cipher2.Decrypt(decrypted[:], encrypted[:])

            if !bytes.Equal(decrypted[:], value[:]) {
                t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
            }
        }
    })
}


func Test_Check(t *testing.T) {
    var key [32]byte
    for i := 0; i < 32; i++ {
        key[i] = byte((i * 2 + 10) % 256)
    }

    ciphertext := "e498cf78cdf1d4a5"
    plaintext := "0001020304050607"

    cipherBytes, _ := hex.DecodeString(ciphertext)
    plainBytes, _ := hex.DecodeString(plaintext)

    for i := 0; i < len(cipherBytes); i += 4 {
        c2 := tool.LE2BE_32(cipherBytes[i:i+4])
        copy(cipherBytes[i:i+4], c2[:])
    }

    for i := 0; i < len(plainBytes); i += 4 {
        p2 := tool.LE2BE_32(plainBytes[i:i+4])
        copy(plainBytes[i:i+4], p2[:])
    }

    cipher, err := NewCipher(key[:], TestSbox2)
    if err != nil {
        t.Fatal(err.Error())
    }

    var encrypted []byte = make([]byte, len(plainBytes))
    cipher.Encrypt(encrypted, plainBytes)

    // 大端转小端
    for i := 0; i < len(encrypted); i += 4 {
        e2 := tool.BE2LE_32(encrypted[i:i+4])
        copy(encrypted[i:i+4], e2[:])
    }

    if ciphertext != fmt.Sprintf("%x", encrypted) {
        t.Errorf("Encrypt error: act=%x, old=%s\n", encrypted, ciphertext)
    }

    // ==========

    cipher2, err := NewCipher(key[:], TestSbox2)
    if err != nil {
        t.Fatal(err.Error())
    }

    var decrypted []byte = make([]byte, len(cipherBytes))
    cipher2.Decrypt(decrypted, cipherBytes)

    // 大端转小端
    for i := 0; i < len(decrypted); i += 4 {
        e2 := tool.BE2LE_32(decrypted[i:i+4])
        copy(decrypted[i:i+4], e2[:])
    }

    if plaintext != fmt.Sprintf("%x", decrypted) {
        t.Errorf("Decrypt error: act=%x, old=%s\n", decrypted, plaintext)
    }
}
