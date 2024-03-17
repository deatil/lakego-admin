package cast256

import (
    "fmt"
    "bytes"
    "testing"
    "math/rand"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/tool"
)

func Test_Cast256(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 5000

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 32)
        random.Read(key)
        value := make([]byte, 16)
        random.Read(value)

        cipher1, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        cipher2, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

// c uchar 强转到 uint32 为小端
func Test_Check(t *testing.T) {
    var key [32]byte

    for i := 0; i < 32; i++ {
        key[i] = byte((i * 2 + 10) % 256)
    }

    ciphertext := "5db4dd765f1d3835615a14afcb5dc2f5"
    plaintext := "000102030405060708090a0b0c0d0e0f"

    cipherBytes, _ := hex.DecodeString(ciphertext)
    plainBytes, _ := hex.DecodeString(plaintext)

    // 小端转大端
    key2 := tool.LE2BE_32_Bytes(key[:])
    cipherBytes = tool.LE2BE_32_Bytes(cipherBytes)
    plainBytes = tool.LE2BE_32_Bytes(plainBytes)

    cipher, err := NewCipher(key2)
    if err != nil {
        t.Fatal(err.Error())
    }

    var encrypted []byte = make([]byte, len(plainBytes))
    cipher.Encrypt(encrypted, plainBytes)

    // 大端转小端
    encrypted = tool.BE2LE_32_Bytes(encrypted[:])

    if ciphertext != fmt.Sprintf("%x", encrypted) {
        t.Errorf("Encrypt error: act=%x, old=%s\n", encrypted, ciphertext)
    }

    // ==========

    cipher2, err := NewCipher(key2)
    if err != nil {
        t.Fatal(err.Error())
    }

    var decrypted []byte = make([]byte, len(cipherBytes))
    cipher2.Decrypt(decrypted, cipherBytes)

    // 大端转小端
    decrypted = tool.BE2LE_32_Bytes(decrypted[:])

    if plaintext != fmt.Sprintf("%x", decrypted) {
        t.Errorf("Decrypt error: act=%x, old=%s\n", decrypted, plaintext)
    }
}

func Test_BE_Check(t *testing.T) {
    var key [32]byte

    for i := 0; i < 32; i++ {
        key[i] = byte((i * 2 + 10) % 256)
    }

    plaintext := "000102030405060708090a0b0c0d0e0f"
    ciphertext := "47cc8266c2221328a7398f2655551d6a"

    cipherBytes, _ := hex.DecodeString(ciphertext)
    plainBytes, _ := hex.DecodeString(plaintext)

    cipher, err := NewCipher(key[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    var encrypted []byte = make([]byte, len(plainBytes))
    cipher.Encrypt(encrypted, plainBytes)

    if ciphertext != fmt.Sprintf("%x", encrypted) {
        t.Errorf("Encrypt error: act=%x, old=%s\n", encrypted, ciphertext)
    }

    // ==========

    cipher2, err := NewCipher(key[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    var decrypted []byte = make([]byte, len(cipherBytes))
    cipher2.Decrypt(decrypted, cipherBytes)

    if plaintext != fmt.Sprintf("%x", decrypted) {
        t.Errorf("Decrypt error: act=%x, old=%s\n", decrypted, plaintext)
    }
}
