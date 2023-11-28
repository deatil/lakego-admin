package saferplus

import (
    "fmt"
    "bytes"
    "testing"
    "math/rand"
    "encoding/hex"
)

func Test_Saferplus(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 500

    var encrypted [8]byte
    var decrypted [8]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 8)
        random.Read(key)
        value := make([]byte, 8)
        random.Read(value)

        cipher, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher.Encrypt(encrypted[:], value)
        cipher.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_Saferplus_Key16(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 500

    var encrypted [8]byte
    var decrypted [8]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 16)
        random.Read(key)
        value := make([]byte, 8)
        random.Read(value)

        cipher, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher.Encrypt(encrypted[:], value)
        cipher.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func test_Check_64byte(t *testing.T) {
    var key [8]byte

    for i := 0; i < 8; i++ {
        key[i] = byte((i * 2 + 10) % 256)
    }

    ciphertext := "e490eebffd908f34"
    plaintext := "0001020304050607"

    plainBytes, _ := hex.DecodeString(plaintext)

    cipher, err := NewCipher(key[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    var encrypted [8]byte
    cipher.Encrypt(encrypted[:], plainBytes)

    if ciphertext != fmt.Sprintf("%x", encrypted) {
        t.Errorf("Encrypt error: act=%x, old=%s\n", encrypted, ciphertext)
    }
}
