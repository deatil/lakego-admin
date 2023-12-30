package rijndael

import (
    "fmt"
    "bytes"
    "testing"
    "crypto/rand"
    "crypto/cipher"
)

var testDatas = []struct {
    bs int
    ks int
    cipher func(key []byte) (cipher.Block, error)
} {
    {
        BlockSize128,
        16,
        NewCipher128,
    },
    {
        BlockSize128,
        20,
        NewCipher128,
    },
    {
        BlockSize128,
        24,
        NewCipher128,
    },
    {
        BlockSize128,
        28,
        NewCipher128,
    },
    {
        BlockSize128,
        32,
        NewCipher128,
    },

    {
        BlockSize160,
        16,
        NewCipher160,
    },
    {
        BlockSize160,
        20,
        NewCipher160,
    },
    {
        BlockSize160,
        24,
        NewCipher160,
    },
    {
        BlockSize160,
        28,
        NewCipher160,
    },
    {
        BlockSize160,
        32,
        NewCipher160,
    },

    {
        BlockSize192,
        16,
        NewCipher192,
    },
    {
        BlockSize192,
        20,
        NewCipher192,
    },
    {
        BlockSize192,
        24,
        NewCipher192,
    },
    {
        BlockSize192,
        28,
        NewCipher192,
    },
    {
        BlockSize192,
        32,
        NewCipher192,
    },

    {
        BlockSize224,
        16,
        NewCipher224,
    },
    {
        BlockSize224,
        20,
        NewCipher224,
    },
    {
        BlockSize224,
        24,
        NewCipher224,
    },
    {
        BlockSize224,
        28,
        NewCipher224,
    },
    {
        BlockSize224,
        32,
        NewCipher224,
    },

    {
        BlockSize256,
        16,
        NewCipher256,
    },
    {
        BlockSize256,
        20,
        NewCipher256,
    },
    {
        BlockSize256,
        24,
        NewCipher256,
    },
    {
        BlockSize256,
        28,
        NewCipher256,
    },
    {
        BlockSize256,
        32,
        NewCipher256,
    },
}

func Test_Cipher(t *testing.T) {
    for _, v := range testDatas {
        max := 200

        var encrypted []byte = make([]byte, v.bs)
        var decrypted []byte = make([]byte, v.bs)

        for i := 0; i < max; i++ {
            key := make([]byte, v.ks)
            rand.Read(key)

            value := make([]byte, v.bs)
            rand.Read(value)

            cipher1, err := v.cipher(key)
            if err != nil {
                t.Fatal(err.Error())
            }

            cipher1.Encrypt(encrypted, value)

            cipher2, err := v.cipher(key)
            if err != nil {
                t.Fatal(err.Error())
            }

            cipher2.Decrypt(decrypted, encrypted)

            if !bytes.Equal(decrypted, value) {
                t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
            }
        }
    }
}

func Test_Check16(t *testing.T) {
    hexcipher := "5352e43763eec1a8502433d6d520b1f0"

    keysize := 16
    blocksize := 16

    var keyword [16]byte
    var plaintext [16]byte

    for j := 0; j < keysize; j++ {
        keyword[j] = 0;
    }
    keyword[0] = 1

    for j := 0; j < blocksize; j++ {
        plaintext[j] = byte(j)
    }

    cipher, err := NewCipher128(keyword[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    var encrypted [16]byte
    cipher.Encrypt(encrypted[:], plaintext[:])

    if hexcipher != fmt.Sprintf("%x", encrypted) {
        t.Errorf("Encrypt error. got %x, want %s", encrypted, hexcipher)
    }

    // ==========

    cipher2, err := NewCipher128(keyword[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    var decrypted [16]byte
    cipher2.Decrypt(decrypted[:], encrypted[:])

    if fmt.Sprintf("%x", decrypted) != fmt.Sprintf("%x", plaintext) {
        t.Errorf("Decrypt error. got %x, want %x", decrypted, plaintext)
    }
}

func Test_Check20(t *testing.T) {
    hexcipher := "8b2c8210d7d0dd80d65006befb6a7030036521cf"

    keysize := 32
    blocksize := 20

    var keyword [32]byte
    var plaintext [20]byte

    for j := 0; j < keysize; j++ {
        keyword[j] = byte((j * 2 + 10) % 256)
    }

    for j := 0; j < blocksize; j++ {
        plaintext[j] = byte(j % 256)
    }

    cipher, err := NewCipher160(keyword[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    var encrypted [20]byte
    cipher.Encrypt(encrypted[:], plaintext[:])

    if hexcipher != fmt.Sprintf("%x", encrypted) {
        t.Errorf("Encrypt error. got %x, want %s", encrypted, hexcipher)
    }

    // ==========

    cipher2, err := NewCipher160(keyword[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    var decrypted [20]byte
    cipher2.Decrypt(decrypted[:], encrypted[:])

    if fmt.Sprintf("%x", decrypted) != fmt.Sprintf("%x", plaintext) {
        t.Errorf("Decrypt error. got %x, want %x", decrypted, plaintext)
    }
}

func Test_Check24(t *testing.T) {
    hexcipher := "380ee49a5de1dbd4b9cc11af60b8c8ff669e367af8948a8a"

    keysize := 32
    blocksize := 24

    var keyword [32]byte
    var plaintext [24]byte

    for j := 0; j < keysize; j++ {
        keyword[j] = byte((j * 2 + 10) % 256)
    }

    for j := 0; j < blocksize; j++ {
        plaintext[j] = byte(j % 256)
    }

    cipher, err := NewCipher192(keyword[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    var encrypted [24]byte
    cipher.Encrypt(encrypted[:], plaintext[:])

    if hexcipher != fmt.Sprintf("%x", encrypted) {
        t.Errorf("Encrypt error. got %x, want %s", encrypted, hexcipher)
    }

    // ==========

    cipher2, err := NewCipher192(keyword[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    var decrypted [24]byte
    cipher2.Decrypt(decrypted[:], encrypted[:])

    if fmt.Sprintf("%x", decrypted) != fmt.Sprintf("%x", plaintext) {
        t.Errorf("Decrypt error. got %x, want %x", decrypted, plaintext)
    }
}

func Test_Check28(t *testing.T) {
    hexcipher := "a0464d3da578253c11b728a6bc61feff01ceabadaa078b62007f3157"

    keysize := 32
    blocksize := 28

    var keyword [32]byte
    var plaintext [28]byte

    for j := 0; j < keysize; j++ {
        keyword[j] = byte((j * 2 + 10) % 256)
    }

    for j := 0; j < blocksize; j++ {
        plaintext[j] = byte(j % 256)
    }

    cipher, err := NewCipher224(keyword[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    var encrypted [28]byte
    cipher.Encrypt(encrypted[:], plaintext[:])

    if hexcipher != fmt.Sprintf("%x", encrypted) {
        t.Errorf("Encrypt error. got %x, want %s", encrypted, hexcipher)
    }

    // ==========

    cipher2, err := NewCipher224(keyword[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    var decrypted [28]byte
    cipher2.Decrypt(decrypted[:], encrypted[:])

    if fmt.Sprintf("%x", decrypted) != fmt.Sprintf("%x", plaintext) {
        t.Errorf("Decrypt error. got %x, want %x", decrypted, plaintext)
    }
}

func Test_Check32(t *testing.T) {
    hexcipher := "45af6c269326fd935edd24733cff74fc1aa358841a6cd80b79f242d983f8ff2e"

    keysize := 32
    blocksize := 32

    var keyword [32]byte
    var plaintext [32]byte

    for j := 0; j < keysize; j++ {
        keyword[j] = byte((j * 2 + 10) % 256)
    }

    for j := 0; j < blocksize; j++ {
        plaintext[j] = byte(j % 256)
    }

    cipher, err := NewCipher256(keyword[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    var encrypted [32]byte
    cipher.Encrypt(encrypted[:], plaintext[:])

    if hexcipher != fmt.Sprintf("%x", encrypted) {
        t.Errorf("Encrypt error. got %x, want %s", encrypted, hexcipher)
    }

    // ==========

    cipher2, err := NewCipher256(keyword[:])
    if err != nil {
        t.Fatal(err.Error())
    }

    var decrypted [32]byte
    cipher2.Decrypt(decrypted[:], encrypted[:])

    if fmt.Sprintf("%x", decrypted) != fmt.Sprintf("%x", plaintext) {
        t.Errorf("Decrypt error. got %x, want %x", decrypted, plaintext)
    }
}
