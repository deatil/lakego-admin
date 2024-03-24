package simon

import (
    "bytes"
    "testing"
    "math/rand"
    "encoding/hex"
)

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

        cipher1, err := NewCipher128(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        cipher2, err := NewCipher128(key)
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

        cipher1, err := NewCipher192(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        cipher2, err := NewCipher192(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

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

        cipher1, err := NewCipher256(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        cipher2, err := NewCipher256(key)
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
           fromHex("2074726176656c6c6572732064657363"),
           fromHex("bc0b4ef82a83aa653ffe541e1e1b6849"),
           fromHex("000102030405060708090a0b0c0d0e0f"),
        },
        {
           24,
           fromHex("72696265207768656e20746865726520"),
           fromHex("5bb897256e8d9c6c4f0ddcfcef61acc4"),
           fromHex("000102030405060708090a0b0c0d0e0f1011121314151617"),
        },
        {
           32,
           fromHex("697320612073696d6f6f6d20696e2074"),
           fromHex("68b8e7ef872af73ba0a3c8af79552b8d"),
           fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
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

func Test_Check128(t *testing.T) {
   tests := []testData{
        {
           16,
           fromHex("2074726176656c6c6572732064657363"),
           fromHex("bc0b4ef82a83aa653ffe541e1e1b6849"),
           fromHex("000102030405060708090a0b0c0d0e0f"),
        },
    }

    for i, test := range tests {
        c, err := NewCipher128(test.key)
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp := make([]byte, BlockSize)
        c.Encrypt(tmp, test.pt)

        if !bytes.Equal(tmp, test.ct) {
            t.Errorf("[%d] Check error: got %x, want %x", i, tmp, test.ct)
        }

        // ===========

        c2, err := NewCipher128(test.key)
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

func Test_Check192(t *testing.T) {
   tests := []testData{
        {
           24,
           fromHex("72696265207768656e20746865726520"),
           fromHex("5bb897256e8d9c6c4f0ddcfcef61acc4"),
           fromHex("000102030405060708090a0b0c0d0e0f1011121314151617"),
        },
    }

    for i, test := range tests {
        c, err := NewCipher192(test.key)
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp := make([]byte, BlockSize)
        c.Encrypt(tmp, test.pt)

        if !bytes.Equal(tmp, test.ct) {
            t.Errorf("[%d] Check error: got %x, want %x", i, tmp, test.ct)
        }

        // ===========

        c2, err := NewCipher192(test.key)
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

func Test_Check256(t *testing.T) {
   tests := []testData{
        {
           32,
           fromHex("697320612073696d6f6f6d20696e2074"),
           fromHex("68b8e7ef872af73ba0a3c8af79552b8d"),
           fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        },
    }

    for i, test := range tests {
        c, err := NewCipher256(test.key)
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp := make([]byte, BlockSize)
        c.Encrypt(tmp, test.pt)

        if !bytes.Equal(tmp, test.ct) {
            t.Errorf("[%d] Check error: got %x, want %x", i, tmp, test.ct)
        }

        // ===========

        c2, err := NewCipher256(test.key)
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
