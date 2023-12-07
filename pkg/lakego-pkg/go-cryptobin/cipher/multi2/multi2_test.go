package multi2

import (
    "bytes"
    "testing"
    "math/rand"
)

func Test_Cipher(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 2

    var encrypted [8]byte
    var decrypted [8]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 40)
        random.Read(key)
        value := make([]byte, 8)
        random.Read(value)

        cipher1, err := NewCipher(key, 128)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        cipher2, err := NewCipher(key, 128)
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
    key []byte
    pt []byte
    ct []byte
    rounds int32
}

func Test_Check(t *testing.T) {
   tests := []testData{
        {
           []byte{
              0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00,

              0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00,

              0x01, 0x23, 0x45, 0x67,
              0x89, 0xAB, 0xCD, 0xEF,
           },
           []byte{
              0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x01,
           },
           []byte{
              0xf8, 0x94, 0x40, 0x84,
              0x5e, 0x11, 0xcf, 0x89,
           },
           128,
        },
        {
           []byte{
              0x35, 0x91, 0x9d, 0x96,
              0x07, 0x02, 0xe2, 0xce,
              0x8d, 0x0b, 0x58, 0x3c,
              0xc9, 0xc8, 0x9d, 0x59,
              0xa2, 0xae, 0x96, 0x4e,
              0x87, 0x82, 0x45, 0xed,
              0x3f, 0x2e, 0x62, 0xd6,
              0x36, 0x35, 0xd0, 0x67,

              0xb1, 0x27, 0xb9, 0x06,
              0xe7, 0x56, 0x22, 0x38,
           },
           []byte{
              0x1f, 0xb4, 0x60, 0x60,
              0xd0, 0xb3, 0x4f, 0xa5,
           },
           []byte{
              0xca, 0x84, 0xa9, 0x34,
              0x75, 0xc8, 0x60, 0xe5,
           },
           216,
        },
    }

    for _, test := range tests {
        c, err := NewCipher(test.key[:], test.rounds)
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp := make([]byte, BlockSize)
        c.Encrypt(tmp, test.pt[:])

        if !bytes.Equal(tmp, test.ct[:]) {
            t.Error("Check Encrypt error")
        }

        // ===========

        c2, err := NewCipher(test.key[:], test.rounds)
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
