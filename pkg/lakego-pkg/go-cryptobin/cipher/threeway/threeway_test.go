package threeway

import (
    "fmt"
    "bytes"
    "testing"
    "math/rand"
    "encoding/hex"
)

func Test_Threeway(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 5000

    var encrypted [12]byte
    var decrypted [12]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 12)
        random.Read(key)
        value := make([]byte, 12)
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

func Test_Check(t *testing.T) {
    var key [12]byte

    for i := 0; i < 12; i++ {
        key[i] = byte((i * 2 + 10) % 256)
    }

    ciphertext := "46823287358d68f6e034ca62"
    plaintext := "000102030405060708090a0b"

    cipherBytes, _ := hex.DecodeString(ciphertext)
    plainBytes, _ := hex.DecodeString(plaintext)

    cipher, err := NewCipher(key[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    var encrypted [12]byte
    cipher.Encrypt(encrypted[:], plainBytes)

    if ciphertext != fmt.Sprintf("%x", encrypted) {
        t.Errorf("Encrypt error: act=%x, old=%s\n", encrypted, ciphertext)
    }

    var decrypted [12]byte
    cipher.Decrypt(decrypted[:], cipherBytes)

    if plaintext != fmt.Sprintf("%x", decrypted) {
        t.Errorf("Decrypt error: act=%x, old=%s\n", decrypted, plaintext)
    }
}
