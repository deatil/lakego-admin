package khazad

import (
    "bytes"
    "testing"
    "math/rand"
)

func Test_Cipher(t *testing.T) {
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

type testData struct {
    pt []byte
    ct []byte
    key []byte
}

func Test_Check(t *testing.T) {
   tests := []testData{
        {
           []byte{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
           []byte{ 0x49, 0xA4, 0xCE, 0x32, 0xAC, 0x19, 0x0E, 0x3F },
           []byte{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        },
        {
           []byte{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
           []byte{ 0x64, 0x5D, 0x77, 0x3E, 0x40, 0xAB, 0xDD, 0x53 },
           []byte{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
        },
        {
           []byte{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
           []byte{ 0x9E, 0x39, 0x98, 0x64, 0xF7, 0x8E, 0xCA, 0x02 },
           []byte{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        },
        {
           []byte{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
           []byte{ 0xA9, 0xDF, 0x3D, 0x2C, 0x64, 0xD3, 0xEA, 0x28 },
           []byte{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        },
    }

    for _, test := range tests {
        c, err := NewCipher(test.key[:])
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp := make([]byte, BlockSize)
        c.Encrypt(tmp, test.pt[:])

        if !bytes.Equal(tmp, test.ct[:]) {
            t.Error("Check error")
        }

        // ===========

        c2, err := NewCipher(test.key[:])
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp2 := make([]byte, BlockSize)
        c2.Decrypt(tmp2, test.ct[:])

        if !bytes.Equal(tmp2, test.pt[:]) {
            t.Error("Check Decrypt error")
        }
    }
}
