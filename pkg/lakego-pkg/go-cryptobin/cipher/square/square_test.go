package square

import (
    "bytes"
    "testing"
    "math/rand"
)

func Test_Square(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 100

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

        // =======

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
    var testkey = []byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")
    var testtext = []byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")
    var cipherText = []byte("\x7c\x34\x91\xd9\x49\x94\xe7\x0f\x0e\xc2\xe7\xa5\xcc\xb5\xa1\x4f")

    var encrypted [16]byte
    var decrypted [16]byte

    cipher1, err := NewCipher(testkey)
    if err != nil {
        t.Fatal(err.Error())
    }

    cipher1.Encrypt(encrypted[:], testtext)

    if !bytes.Equal(encrypted[:], cipherText) {
        t.Errorf("encryption failed, got %x, want %x \n", encrypted, cipherText)
    }

    // ==========

    cipher2, err := NewCipher(testkey)
    if err != nil {
        t.Fatal(err.Error())
    }

    cipher2.Decrypt(decrypted[:], cipherText)

    if !bytes.Equal(decrypted[:], testtext[:]) {
        t.Errorf("decryption failed, got %x, want %x \n", decrypted, testtext)
    }
}
