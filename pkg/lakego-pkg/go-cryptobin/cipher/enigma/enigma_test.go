package enigma

import (
    "fmt"
    "bytes"
    "testing"
    "math/rand"
    "encoding/hex"
)

func Test_Enigma(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 5000

    var encrypted [12]byte
    var decrypted [12]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 13)
        random.Read(key)
        value := make([]byte, 12)
        random.Read(value)

        cipher1, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.XORKeyStream(encrypted[:], value)

        cipher2, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.XORKeyStream(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_Check(t *testing.T) {
    var key [13]byte

    key2 := []byte("enadyotr")
    copy(key[:8], key2)

    ciphertext := "f3edda7da20f8975884600f014d32c7a08e59d7b"
    plaintext := "000102030405060708090a0b0c0d0e0f10111213"

    cipherBytes, _ := hex.DecodeString(ciphertext)
    plainBytes, _ := hex.DecodeString(plaintext)

    cipher, err := NewCipher(key[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    encrypted := make([]byte, len(plainBytes))
    cipher.XORKeyStream(encrypted, plainBytes)

    if ciphertext != fmt.Sprintf("%x", encrypted) {
        t.Errorf("Encrypt error: act=%x, old=%s\n", encrypted, ciphertext)
    }

    cipher2, err := NewCipher(key[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    decrypted := make([]byte, len(cipherBytes))
    cipher2.XORKeyStream(decrypted, cipherBytes)

    if plaintext != fmt.Sprintf("%x", decrypted) {
        t.Errorf("Decrypt error: act=%x, old=%s\n", decrypted, plaintext)
    }
}
