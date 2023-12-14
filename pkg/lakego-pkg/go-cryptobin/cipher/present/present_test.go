package present

import (
    "bytes"
    "testing"
    "math/rand"
    "encoding/hex"
)

func Test_Key10(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 500

    var encrypted [8]byte
    var decrypted [8]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 10)
        random.Read(key)
        value := make([]byte, 8)
        random.Read(value)

        cipher1, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        // =====

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

func Test_Key16(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 500

    var encrypted [8]byte
    var decrypted [8]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 16)
        random.Read(key)
        value := make([]byte, 8)
        random.Read(value)

        cipher1, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        // =====

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

var testDatas = []struct {
    key string
    plain string
    cipher string
} {
    {
        "12345678901234561234567890123456",
        "0000000000000000",
        "d9e1206977a3194b",
    },
    {
        "12345678901234567890",
        "0000000000000000",
        "b525a26a6aa02e38",
    },
}

func Test_Check(t *testing.T) {
    for _, v := range testDatas {
        keyBytes, _ := hex.DecodeString(v.key)
        plainBytes, _ := hex.DecodeString(v.plain)
        cipherBytes, _ := hex.DecodeString(v.cipher)

        c, err := NewCipher(keyBytes)
        if err != nil {
            t.Fatal(err.Error())
        }

        var encrypted []byte = make([]byte, len(plainBytes))
        c.Encrypt(encrypted[:], plainBytes)

        if !bytes.Equal(encrypted, cipherBytes) {
            t.Errorf("encryption/decryption failed: %x != %x\n", encrypted, cipherBytes)
        }
    }
}
