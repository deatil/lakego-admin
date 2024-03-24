package cast

import (
    "bytes"
    "testing"
    "math/rand"
    "encoding/hex"
)

func Test_Key256(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 100

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 32)
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

func Test_Key224(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 100

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 28)
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

func Test_Key192(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 100

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 24)
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

func Test_Key160(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 100

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 20)
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

func Test_Key128(t *testing.T) {
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
           32,
           fromHex("000000000000000000000000bdf4e311"),
           fromHex("fa5874ab5aba5c0ba20aa82124c8f5a5"),
           fromHex("2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604"),
        },
        {
           32,
           fromHex("000000000000000000000000bef5e412"),
           fromHex("7b009fbc0188e770acf8f05d7c5a3144"),
           fromHex("2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604"),
        },

        {
           24,
           fromHex("000000000000000000000000de255aff"),
           fromHex("2bc1929f301347a99d3f3e45ad3401e8"),
           fromHex("2342bb9efa38542cbed0ac83940ac298bac77a7717942863"),
        },
        {
           24,
           fromHex("000000000000000000000000e2295f03"),
           fromHex("bfeaf5bc2b1bcbbe32a93b9900365923"),
           fromHex("2342bb9efa38542cbed0ac83940ac298bac77a7717942863"),
        },

        {
           16,
           fromHex("0000000000000000000000000c9b2807"),
           fromHex("963a8a50ceb54d08e0dee0f1d0413dcf"),
           fromHex("2342bb9efa38542c0af75647f29f615d"),
        },
        {
           16,
           fromHex("0000000000000000000000002cbb4827"),
           fromHex("8665cc6b51b46b7e9b270296c3fd2053"),
           fromHex("2342bb9efa38542c0af75647f29f615d"),
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
