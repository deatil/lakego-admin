package belt

import (
    "bytes"
    "testing"
    "math/rand"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func Test_Key(t *testing.T) {
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
            t.Errorf("encryption/decryption failed: got %x, want %x", decrypted, value)
        }
    }
}

type testData struct {
    pt []byte
    ct []byte
    key []byte
}

func Test_Check_List(t *testing.T) {
   tests := []testData{
        // 32 bytes
        {
           fromHex("000000000000000000000000bdf4e311"),
           fromHex("74bc468e2d40f5839633370e7d67bd23"),
           fromHex("2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604"),
        },
        {
           fromHex("000000000000000000000000cf05f422"),
           fromHex("05ceae72f09bc0d7dfa4978903a5c936"),
           fromHex("2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604"),
        },
        {
           fromHex("000000000000000000000000f0271543"),
           fromHex("47b67fd2f8a41cf50f6526d874f9e692"),
           fromHex("2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604"),
        },

        // 24 bytes
        {
           fromHex("000000000000000000000000de255aff"),
           fromHex("312de1e84c285f8a4c3ee45de9a8bacc"),
           fromHex("2342bb9efa38542cbed0ac83940ac298bac77a7717942863"),
        },
        {
           fromHex("000000000000000000000000e2295f03"),
           fromHex("79172557ae7da54f7d5adb4dcb0ec0d3"),
           fromHex("2342bb9efa38542cbed0ac83940ac298bac77a7717942863"),
        },

        // 16 bytes
        {
           fromHex("0000000000000000000000000c9b2807"),
           fromHex("c362d0c8e930486e00df76023439047d"),
           fromHex("2342bb9efa38542c0af75647f29f615d"),
        },
        {
           fromHex("0000000000000000000000002cbb4827"),
           fromHex("98c02f6582e88b61ed3e0235a361c18a"),
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
