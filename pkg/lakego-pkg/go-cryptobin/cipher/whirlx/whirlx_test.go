package whirlx

import (
    "fmt"
    "bytes"
    "testing"
    "math/rand"
    "encoding/hex"
)

func Test_Whirlx16(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 500

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 16)
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

func Test_Whirlx32(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 500

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

func Test_Check(t *testing.T) {
    var key [16]byte

    for i := 0; i < 16; i++ {
        key[i] = byte((i * 5 + 10) % 0xff)
    }

    ciphertext := "f30be27886fe426cc1e56af3d1229228"
    plaintext := "05060708090a0b0c0d0e0f1011121314"

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

func Test_Fail(t *testing.T) {
    var key [15]byte

    for i := 0; i < 15; i++ {
        key[i] = byte((i * 5 + 10) % 0xff)
    }

    _, err := NewCipher(key[:])
    if err == nil {
        t.Fatal("need error return")
    }

    check := "go-cryptobin/whirlx: invalid key size (must be 16 or 32 bytes)"
    if err.Error() != check {
        t.Errorf("New error: act=%s, check=%s\n", err, check)
    }
}
