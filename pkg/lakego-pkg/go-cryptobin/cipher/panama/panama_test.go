package panama

import (
    "fmt"
    "bytes"
    "testing"
    "math/rand"
    "encoding/hex"
)

func Test_Panama(t *testing.T) {
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
    var key [32]byte
    for i := 0; i < 32; i++ {
        key[i] = byte((i * 2 + 10) % 256)
    }

    var plaintext [20]byte
    for ii := 0; ii < 20; ii++ {
        plaintext[ii] = byte(ii % 256)
    }

    ciphertext := "9644f82d74e6e7b11a1acbb20f4a1c93b800e248"
    // ciphertext := "d76e3c2243feadd2c99edfcb95c64c852ba6c59f"

    cipherBytes, _ := hex.DecodeString(ciphertext)

    cipher, err := NewCipher(key[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    var encrypted []byte = make([]byte, len(plaintext))
    cipher.XORKeyStream(encrypted, plaintext[:])

    if ciphertext != fmt.Sprintf("%x", encrypted) {
        t.Errorf("Encrypt error: act=%x, old=%s\n", encrypted, ciphertext)
    }

    // ==========

    cipher2, err := NewCipher(key[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    var decrypted []byte = make([]byte, len(cipherBytes))
    cipher2.XORKeyStream(decrypted, cipherBytes)

    if fmt.Sprintf("%x", plaintext) != fmt.Sprintf("%x", decrypted) {
        t.Errorf("Decrypt error: act=%x, old=%x\n", decrypted, plaintext)
    }
}
