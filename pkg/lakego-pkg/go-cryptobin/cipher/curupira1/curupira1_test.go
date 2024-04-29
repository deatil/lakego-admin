package curupira1

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

func Test_Cipher(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 100

    var encrypted [12]byte
    var decrypted [12]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 12)
        random.Read(key)
        value := make([]byte, 12)
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
            t.Errorf("encryption/decryption failed, got %x, want %x\n", decrypted, value)
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
        // 96 bits
        {
           fromHex("000000000000000000000000"),
           fromHex("126b5eae509b2e929b1b08ff"),
           fromHex("800000000000000000000000"),
        },
        {
           fromHex("000000000000000000000000"),
           fromHex("f505025bbd6d24e6e0827422"),
           fromHex("000800000000000000000000"),
        },
        {
           fromHex("00f0f0f000f0f0f000f0f0f0"),
           fromHex("6868f79f7850d269d320086c"),
           fromHex("f0f0f0f0f0f0f0f0f0f0f0f0"),
        },

        // 144 bits
        {
           fromHex("000000000000000000000000"),
           fromHex("9d48b60b7808a6c9ffe698dd"),
           fromHex("008000000000000000000000000000000000"),
        },
        {
           fromHex("000000000000000000000000"),
           fromHex("45dac2446a855db096c75465"),
           fromHex("000200000000000000000000000000000000"),
        },
        {
           fromHex("00fdfdfd00fdfdfd00fdfdfd"),
           fromHex("4f43f354c4a5807f277ba802"),
           fromHex("fdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfd"),
        },

        // 192 bits
        {
           fromHex("000000000000000000000000"),
           fromHex("1f6178577467af7494ac6664"),
           fromHex("000200000000000000000000000000000000000000000000"),
        },
        {
           fromHex("000000000000000000000000"),
           fromHex("0ef889e7946f47a56f224a36"),
           fromHex("800000000000000000000000000000000000000000000000"),
        },
        {
           fromHex("000303030003030300030303"),
           fromHex("fd2d3f8ea95d3503cac89165"),
           fromHex("030303030303030303030303030303030303030303030303"),
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
            t.Errorf("Check error, got %x, want %x", tmp, test.ct)
        }

        // ===========

        c2, err := NewCipher(test.key[:])
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp2 := make([]byte, BlockSize)
        c2.Decrypt(tmp2, test.ct[:])

        if !bytes.Equal(tmp2, test.pt[:]) {
            t.Errorf("Check Decrypt error, got %x, want %x", tmp2, test.pt)
        }
    }
}

type testMarvinData struct {
    key []byte
    msg []byte
    tag04 []byte
    tag08 []byte
    tag12 []byte
}

func Test_Marvin_Check(t *testing.T) {
   tests := []testMarvinData{
        {
           fromHex("000000000000000000000000"),
           fromHex("00"),
           fromHex("98b18790"),
           fromHex("d9422e078c210409"),
           fromHex("cf62e6370e635b78e7ce6042"),
        },
        {
           fromHex("0102030405060708090a0b0c"),
           fromHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b"),
           fromHex("22f3fe20"),
           fromHex("c8bb9cd6899f7996"),
           fromHex("8184829a0ca81e375497265e"),
        },
        {
           fromHex("000000000000000000000000"),
           fromHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021"),
           fromHex("2e71647e"),
           fromHex("488ae0d4e8b3ed33"),
           fromHex("c785016594a9c259c819dcf8"),
        },
    }

    for _, test := range tests {
        c, err := NewCipher(test.key[:])
        if err != nil {
            t.Fatal(err.Error())
        }

        mm := NewMarvin(c, nil, false)
        mm.Update(test.msg[:])

        tag04result := mm.GetTag(nil, 32)
        tag08result := mm.GetTag(nil, 64)
        tag12result := mm.GetTag(nil, 96)

        if !bytes.Equal(tag04result, test.tag04) {
            t.Errorf("tag04, got %x, want %x", tag04result, test.tag04)
        }
        if !bytes.Equal(tag08result, test.tag08) {
            t.Errorf("tag08, got %x, want %x", tag08result, test.tag08)
        }
        if !bytes.Equal(tag12result, test.tag12) {
            t.Errorf("tag12, got %x, want %x", tag12result, test.tag12)
        }
    }
}

type testLetterSoupData struct {
    key []byte
    nonce []byte
    msg []byte
    aad []byte
    result []byte
    tag04 []byte
    tag08 []byte
    tag12 []byte
}

func Test_LetterSoup_Check(t *testing.T) {
   tests := []testLetterSoupData{
        {
           fromHex("0102030405060708090a0b0c"),
           fromHex("0102030405060708090a0b0c"),
           fromHex("00"),
           fromHex(""),
           fromHex("90"),
           fromHex("72e567f3"),
           fromHex("88f8ba7d0810f0bf"),
           fromHex("ce6855d3dd3cac207aebc664"),
        },
        {
           fromHex("0102030405060708090a0b0c"),
           fromHex("0102030405060708090a0b0c"),
           fromHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132"),
           fromHex(""),
           fromHex("91bb9a794d74410283ef0de507bf32f63848460ee677c1b9a73ff3b4b3bec2323270f68fe3e23858ec67e83d6dda6bbc5ad1"),
           fromHex("d5a154fd"),
           fromHex("cf27d0441bfca586"),
           fromHex("627330fccf6c1052b2799dab"),
        },
        {
           fromHex("0102030405060708090a0b0c"),
           fromHex("0102030405060708090a0b0c"),
           fromHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738"),
           fromHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738"),
           fromHex("91bb9a794d74410283ef0de507bf32f63848460ee677c1b9a73ff3b4b3bec2323270f68fe3e23858ec67e83d6dda6bbc5ad11a70ce93b87a"),
           fromHex("7d45ed5d"),
           fromHex("41dbb4bdaa3e60ff"),
           fromHex("71970daf0ac3e16454b5422d"),
        },

        {
           fromHex("0102030405060708090a0b0c"),
           fromHex("000000000000000000000000"),
           fromHex("0000000000"),
           fromHex(""),
           fromHex("e7c05f0196"),
           fromHex("a0a574e1"),
           fromHex("2b65762460e5b2ca"),
           fromHex("2ba17ab21654b82eb1d5c645"),
        },
        {
           fromHex("0102030405060708090a0b0c"),
           fromHex("000000000000000000000000"),
           fromHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c"),
           fromHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c"),
           fromHex("e6c25c0593144e758954ab9236bf0e86b433fc9022b59db3fe72a24597faaee1bb3f1bf931493e79623f7d517e44ec26f9ce98b242077528849c4678"),
           fromHex("53c70778"),
           fromHex("9ee6c609fdfc8016"),
           fromHex("c04a50a68a1cf1328a697cfc"),
        },
    }

    for _, test := range tests {
        {
            c, err := NewCipher(test.key[:])
            if err != nil {
                t.Fatal(err.Error())
            }

            mac := NewMarvin(c, nil, true)

            aead := NewLetterSoupWithMAC(c, mac)
            aead.SetIV(test.nonce[:])

            cipher := make([]byte, len(test.msg))
            aead.Encrypt(cipher, test.msg)

            if len(test.aad) != 0 {
                aead.Update(test.aad[:])
            }

            tag04result := aead.GetTag(nil, 32)
            tag08result := aead.GetTag(nil, 64)
            tag12result := aead.GetTag(nil, 96)

            decrypted := make([]byte, len(test.result))
            aead.Decrypt(decrypted, test.result)

            if !bytes.Equal(test.result, cipher) {
                t.Errorf("Encrypt, got %x, want %x", cipher, test.result)
            }
            if !bytes.Equal(tag04result, test.tag04) {
                t.Errorf("tag04, got %x, want %x", tag04result, test.tag04)
            }
            if !bytes.Equal(tag08result, test.tag08) {
                t.Errorf("tag08, got %x, want %x", tag08result, test.tag08)
            }
            if !bytes.Equal(tag12result, test.tag12) {
                t.Errorf("tag12, got %x, want %x", tag12result, test.tag12)
            }
            if !bytes.Equal(test.msg, decrypted) {
                t.Errorf("Decrypt, got %x, want %x", decrypted, test.msg)
            }
        }

        // ===========

        {
            c, err := NewCipher(test.key[:])
            if err != nil {
                t.Fatal(err.Error())
            }

            aead := NewLetterSoup(c)
            aead.SetIV(test.nonce[:])

            cipher := make([]byte, len(test.msg))
            aead.Encrypt(cipher, test.msg)

            if len(test.aad) != 0 {
                aead.Update(test.aad[:])
            }

            tag04result := aead.GetTag(nil, 32)
            tag08result := aead.GetTag(nil, 64)
            tag12result := aead.GetTag(nil, 96)

            decrypted := make([]byte, len(test.result))
            aead.Decrypt(decrypted, test.result)

            if !bytes.Equal(test.result, cipher) {
                t.Errorf("Encrypt, got %x, want %x", cipher, test.result)
            }
            if !bytes.Equal(tag04result, test.tag04) {
                t.Errorf("tag04, got %x, want %x", tag04result, test.tag04)
            }
            if !bytes.Equal(tag08result, test.tag08) {
                t.Errorf("tag08, got %x, want %x", tag08result, test.tag08)
            }
            if !bytes.Equal(tag12result, test.tag12) {
                t.Errorf("tag12, got %x, want %x", tag12result, test.tag12)
            }
            if !bytes.Equal(test.msg, decrypted) {
                t.Errorf("Decrypt, got %x, want %x", decrypted, test.msg)
            }
        }
    }
}
