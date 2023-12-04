package rc2

import (
    "bytes"
    "testing"
    "math/rand"
)

func Test_Lea_Key16(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 5000

    var encrypted [8]byte
    var decrypted [8]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 16)
        random.Read(key)
        value := make([]byte, 8)
        random.Read(value)

        cipher1, err := NewCipher(key, len(key)*8)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        cipher2, err := NewCipher(key, len(key)*8)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}
