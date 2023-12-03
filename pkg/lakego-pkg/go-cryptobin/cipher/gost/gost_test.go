package gost

import (
    "bytes"
    "testing"
    "math/rand"
)

func Test_Gost(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 5000

    var encrypted [8]byte
    var decrypted [8]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 32)
        random.Read(key)
        value := make([]byte, 8)
        random.Read(value)

        cipher1, err := NewCipher(key, DESDerivedSbox)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        cipher2, err := NewCipher(key, DESDerivedSbox)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}
