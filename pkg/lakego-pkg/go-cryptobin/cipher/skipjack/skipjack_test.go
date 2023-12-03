package skipjack

import (
    "bytes"
    "testing"
    "math/rand"
)

func Test_Skipjack(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 5000

    var encrypted [8]byte
    var decrypted [8]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 10)
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
