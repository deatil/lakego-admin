package trivium

import (
    "bytes"
    "testing"
    "math/rand"
    "encoding/hex"
)

func Test_Cipher(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 500

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 10)
        random.Read(key)
        iv := make([]byte, 10)
        random.Read(iv)
        value := make([]byte, 16)
        random.Read(value)

        cipher1, err := NewCipher(key, iv)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.XORKeyStream(encrypted[:], value)

        // =====

        cipher2, err := NewCipher(key, iv)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.XORKeyStream(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

var testDatas = []struct {
    key string
    iv string
    plain string
    cipher string
} {
    {
        "80000000000000000000",
        "12345678901234567890",
        "00000000000000000000000000000000",
        "70487E6E665D10C3DBF9932890C7F481",
    },
}

func Test_Check(t *testing.T) {
    for _, v := range testDatas {
        keyBytes, _ := hex.DecodeString(v.key)
        ivBytes, _ := hex.DecodeString(v.iv)
        plainBytes, _ := hex.DecodeString(v.plain)
        cipherBytes, _ := hex.DecodeString(v.cipher)

        c, err := NewCipher(keyBytes, ivBytes)
        if err != nil {
            t.Fatal(err.Error())
        }

        var encrypted []byte = make([]byte, len(plainBytes))
        c.XORKeyStream(encrypted[:], plainBytes)

        if !bytes.Equal(encrypted, cipherBytes) {
            t.Errorf("encryption/decryption failed: %x != %x\n", encrypted, cipherBytes)
        }
    }
}
