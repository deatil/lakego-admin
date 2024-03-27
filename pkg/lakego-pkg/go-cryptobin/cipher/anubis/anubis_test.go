package anubis

import (
    "bytes"
    "testing"
    "math/rand"
    "encoding/hex"
)

func Test_Cipher(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 100

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 40)
        random.Read(key)
        value := make([]byte, 16)
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

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

type testData struct {
    keylen int32
    pt []byte
    ct []byte
    key []byte
}

func Test_Check(t *testing.T) {
   tests := []testData{
        {
           16,
           fromHex("00000000000000000000000000000000"),
           fromHex("B835BDC334829D8371BFA371E4B3C4FD"),
           fromHex("80000000000000000000000000000000"),
        },
        {
           16,
           fromHex("00000000000000000000000000000000"),
           fromHex("7899F4F9FDA441B23C8C6DCB95D421EC"),
           fromHex("00000000000000000200000000000000"),
        },

           /* 160-bit keys */
        {
           20,
           fromHex("00000000000000000000000000000000"),
           fromHex("F821AE3BB8FA31BD6F54FE6E1D3D52C4"),
           fromHex("2000000000000000000000000000000000000000"),
        },
        {
           20,
           fromHex("FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE"),
           fromHex("83DA3D4D34E1DFAED77629FCEDD3B9CB"),
           fromHex("FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE"),
        },

          /* 192-bit keys */
        {
           24,
           fromHex("00000000000000000000000000000000"),
           fromHex("3E451F4425CEA9DE37FFE0134BD5693B"),
           fromHex("020000000000000000000000000000000000000000000000"),
        },
        {
           24,
           fromHex("FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE"),
           fromHex("BA6072F91C7FDE342397FDC15607A941"),
           fromHex("FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE"),
        },

          /* 224-bit keys */
        {
           28,
           fromHex("00000000000000000000000000000000"),
           fromHex("680228A3F94B520B53CE7CF614373418"),
           fromHex("08000000000000000000000000000000000000000000000000000000"),
        },
        {
           28,
           fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
           fromHex("5F67506B32D3A8F2944FA65AE79218C3"),
           fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        },

          /* 256-bit keys */
        {
           32,
           fromHex("00000000000000000000000000000000"),
           fromHex("59BF80DACA4BA8A520678CCFA6763065"),
           fromHex("0100000000000000000000000000000000000000000000000000000000000000"),
        },
        {
           32,
           fromHex("FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD"),
           fromHex("AD2C6AE8ADD786F1B853BFE1995AF58D"),
           fromHex("FDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFD"),
        },

          /* 288-bit keys */
        {
           36,
           fromHex("00000000000000000000000000000000"),
           fromHex("81CFE0332B0923AEAC27EC96623D6581"),
           fromHex("000800000000000000000000000000000000000000000000000000000000000000000000"),
        },
        {
           36,
           fromHex("FAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFA"),
           fromHex("CC3254263A92774AC7A5E085EF6EAD46"),
           fromHex("FAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFA"),
        },

          /* 320-bit keys */
        {
           40,
           fromHex("00000000000000000000000000000000"),
           fromHex("B5865DEF7A0E9E3206E2523BA07C37CC"),
           fromHex("00001000000000000000000000000000000000000000000000000000000000000000000000000000"),
        },
        {
           40,
           fromHex("F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7"),
           fromHex("D301C5F818349203A5A952E3FF767227"),
           fromHex("F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7"),
        },
    }

    for i, test := range tests {
        c, err := NewCipher(test.key)
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp := make([]byte, BlockSize)
        c.Encrypt(tmp, test.pt)

        if !bytes.Equal(tmp, test.ct) {
            t.Errorf("[%d] Check error: got %x, want %x", i, tmp, test.ct)
        }

        // ===========

        c2, err := NewCipher(test.key)
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp2 := make([]byte, BlockSize)
        c2.Decrypt(tmp2, test.ct)

        if !bytes.Equal(tmp2, test.pt) {
            t.Errorf("[%d] Check Decrypt error: got %x, want %x", i, tmp2, test.pt)
        }
    }
}
