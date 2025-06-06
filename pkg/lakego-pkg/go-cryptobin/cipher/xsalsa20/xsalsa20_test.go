package xsalsa20

import (
    "bytes"
    "testing"
    "math/rand"
)

func Test_NewCipher(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 5000

    var encrypted [12]byte
    var decrypted [12]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 32)
        random.Read(key)
        value := make([]byte, 12)
        random.Read(value)
        nonce := make([]byte, 24)
        random.Read(nonce)

        cipher1, err := NewCipher(key, nonce)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.XORKeyStream(encrypted[:], value)

        if bytes.Equal(encrypted[:], value[:]) {
            t.Errorf("fail: encrypted equal value\n")
        }

        cipher2, err := NewCipher(key, nonce)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.XORKeyStream(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_NewCipherWithCounter(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 5000

    var encrypted [12]byte
    var decrypted [12]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 32)
        random.Read(key)
        value := make([]byte, 12)
        random.Read(value)
        nonce := make([]byte, 24)
        random.Read(nonce)

        cipher1, err := NewCipherWithCounter(key, nonce, 2)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.XORKeyStream(encrypted[:], value)

        if bytes.Equal(encrypted[:], value[:]) {
            t.Errorf("fail: encrypted equal value\n")
        }

        cipher2, err := NewCipherWithCounter(key, nonce, 2)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.XORKeyStream(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}
