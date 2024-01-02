package serpent

import (
    "bytes"
    "reflect"
    "testing"
    "math/rand"
    "encoding/hex"
)

func Test_Serpent(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 500

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 16)
        random.Read(key)
        value := make([]byte, 16)
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
    key := "0123456789abcdeffedcba9876543210"
    plaintext := "012acba789abcdeffedcba9876543210"
    ciphertext := "0644eb39a872cd8aab070b35bd5e4fc9"

    keyBytes, _ := hex.DecodeString(key)
    plaintextBytes, _ := hex.DecodeString(plaintext)
    ciphertextBytes, _ := hex.DecodeString(ciphertext)


    c, err := NewCipher(keyBytes)
    if err != nil {
        t.Fatal(err)
    }

    dst := make([]byte, len(plaintextBytes))
    c.Encrypt(dst, plaintextBytes)
    if !reflect.DeepEqual(dst, ciphertextBytes) {
        t.Errorf("got=%x, want=%x\n", dst, ciphertextBytes)
    }

    c2, err := NewCipher(keyBytes)
    if err != nil {
        t.Fatal(err)
    }

    c2.Decrypt(dst, ciphertextBytes)
    if !reflect.DeepEqual(dst, plaintextBytes) {
        t.Errorf("got=%x, want=%x\n", dst, plaintextBytes)
    }
}
