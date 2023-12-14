package mars2

import (
    "bytes"
    "testing"
    "math/rand"
    "encoding/hex"
)

func Test_Mars(t *testing.T) {
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

func Test_Mars_Key24(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 500

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 24)
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

func Test_Mars_Key32(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 500

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 32)
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

var testDatas = []struct {
    key string
    plain string
    cipher string
} {
    {
        "80000000000000000000000000000000",
        "00000000000000000000000000000000",
        "BB2042299A71DB4DA474ACB221B9B7D3",
    },
    {
        "CB14A1776ABBC1CDAFE7243DEF2CEA02",
        "F94512A9B42D034EC4792204D708A69B",
        "4DF955AD5B398D66408D620A2B27E1A9",
    },
    {
        "00000000000000000000000000000000",
        "DCC07B8DFB0738D6E30A22DFCF27E886",
        "11AD65A44A77D33A729CCEE05AA585AE",
    },
}

func Test_Check_Encrypt(t *testing.T) {
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
