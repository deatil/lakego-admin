package kalyna

import (
    "bytes"
    "testing"
    "math/rand"
    "encoding/hex"
)

func Test_Key512_512(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 100

    var encrypted [64]byte
    var decrypted [64]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 64)
        random.Read(key)
        value := make([]byte, 64)
        random.Read(value)

        cipher1, err := NewCipher512_512(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        cipher2, err := NewCipher512_512(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_Key256_512(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 100

    var encrypted [32]byte
    var decrypted [32]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 64)
        random.Read(key)
        value := make([]byte, 32)
        random.Read(value)

        cipher1, err := NewCipher256_512(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        cipher2, err := NewCipher256_512(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_Key256_256(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 100

    var encrypted [32]byte
    var decrypted [32]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 32)
        random.Read(key)
        value := make([]byte, 32)
        random.Read(value)

        cipher1, err := NewCipher256_256(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        cipher2, err := NewCipher256_256(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_Key128_256(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 100

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 32)
        random.Read(key)
        value := make([]byte, 16)
        random.Read(value)

        cipher1, err := NewCipher128_256(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        cipher2, err := NewCipher128_256(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_Key128_128(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 100

    var encrypted [16]byte
    var decrypted [16]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 16)
        random.Read(key)
        value := make([]byte, 16)
        random.Read(value)

        cipher1, err := NewCipher128_128(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        cipher2, err := NewCipher128_128(key)
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
           64,
           fromHex("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"),
           fromHex("4A26E31B811C356AA61DD6CA0596231A67BA8354AA47F3A13E1DEEC320EB56B895D0F417175BAB662FD6F134BB15C86CCB906A26856EFEB7C5BC6472940DD9D9"),
           fromHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"),
        },
        {
           64,
           fromHex("CE80843325A052521BEAD714E6A9D829FD381E0EE9A845BD92044554D9FA46A3757FEFDB853BB1F297FF9D833B75E66AAF4157ABB5291BDCF094BB13AA5AFF22"),
           fromHex("7F7E7D7C7B7A797877767574737271706F6E6D6C6B6A696867666564636261605F5E5D5C5B5A595857565554535251504F4E4D4C4B4A49484746454443424140"),
           fromHex("3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100"),
        },

        {
           32,
           fromHex("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"),
           fromHex("F66E3D570EC92135AEDAE323DCBD2A8CA03963EC206A0D5A88385C24617FD92C"),
           fromHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        },
        {
           32,
           fromHex("7FC5237896674E8603C1E9B03F8B4BA3AB5B7C592C3FC3D361EDD12586B20FE3"),
           fromHex("3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A29282726252423222120"),
           fromHex("1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100"),
        },

        {
           16,
           fromHex("101112131415161718191A1B1C1D1E1F"),
           fromHex("81BF1C7D779BAC20E1C9EA39B4D2AD06"),
           fromHex("000102030405060708090A0B0C0D0E0F"),
        },
        {
           16,
           fromHex("7291EF2B470CC7846F09C2303973DAD7"),
           fromHex("1F1E1D1C1B1A19181716151413121110"),
           fromHex("0F0E0D0C0B0A09080706050403020100"),
        },
    }

    for i, test := range tests {
        c, err := NewCipher(test.key)
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp := make([]byte, len(test.pt))
        c.Encrypt(tmp, test.pt)

        if !bytes.Equal(tmp, test.ct) {
            t.Errorf("[%d] Check error: got %x, want %x", i, tmp, test.ct)
        }

        // ===========

        c2, err := NewCipher(test.key)
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp2 := make([]byte, len(test.ct))
        c2.Decrypt(tmp2, test.ct)

        if !bytes.Equal(tmp2, test.pt) {
            t.Errorf("[%d] Check Decrypt error: got %x, want %x", i, tmp2, test.pt)
        }
    }
}

func Test_Check512_512(t *testing.T) {
   tests := []testData{
        {
           64,
           fromHex("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"),
           fromHex("4A26E31B811C356AA61DD6CA0596231A67BA8354AA47F3A13E1DEEC320EB56B895D0F417175BAB662FD6F134BB15C86CCB906A26856EFEB7C5BC6472940DD9D9"),
           fromHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"),
        },
        {
           64,
           fromHex("CE80843325A052521BEAD714E6A9D829FD381E0EE9A845BD92044554D9FA46A3757FEFDB853BB1F297FF9D833B75E66AAF4157ABB5291BDCF094BB13AA5AFF22"),
           fromHex("7F7E7D7C7B7A797877767574737271706F6E6D6C6B6A696867666564636261605F5E5D5C5B5A595857565554535251504F4E4D4C4B4A49484746454443424140"),
           fromHex("3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100"),
        },
    }

    for i, test := range tests {
        c, err := NewCipher512_512(test.key)
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp := make([]byte, len(test.pt))
        c.Encrypt(tmp, test.pt)

        if !bytes.Equal(tmp, test.ct) {
            t.Errorf("[%d] Check error: got %x, want %x", i, tmp, test.ct)
        }

        // ===========

        c2, err := NewCipher512_512(test.key)
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp2 := make([]byte, len(test.ct))
        c2.Decrypt(tmp2, test.ct)

        if !bytes.Equal(tmp2, test.pt) {
            t.Errorf("[%d] Check Decrypt error: got %x, want %x", i, tmp2, test.pt)
        }
    }
}

func Test_Check256_512(t *testing.T) {
   tests := []testData{
        {
           64,
           fromHex("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"),
           fromHex("606990E9E6B7B67A4BD6D893D72268B78E02C83C3CD7E102FD2E74A8FDFE5DD9"),
           fromHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"),
        },
        {
           64,
           fromHex("18317A2767DAD482BCCD07B9A1788D075E7098189E5F84972D0B916D79BA6AE0"),
           fromHex("5F5E5D5C5B5A595857565554535251504F4E4D4C4B4A49484746454443424140"),
           fromHex("3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100"),
        },
    }

    for i, test := range tests {
        c, err := NewCipher256_512(test.key)
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp := make([]byte, len(test.pt))
        c.Encrypt(tmp, test.pt)

        if !bytes.Equal(tmp, test.ct) {
            t.Errorf("[%d] Check error: got %x, want %x", i, tmp, test.ct)
        }

        // ===========

        c2, err := NewCipher256_512(test.key)
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp2 := make([]byte, len(test.ct))
        c2.Decrypt(tmp2, test.ct)

        if !bytes.Equal(tmp2, test.pt) {
            t.Errorf("[%d] Check Decrypt error: got %x, want %x", i, tmp2, test.pt)
        }
    }
}

func Test_Check256_256(t *testing.T) {
   tests := []testData{
        {
           32,
           fromHex("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"),
           fromHex("F66E3D570EC92135AEDAE323DCBD2A8CA03963EC206A0D5A88385C24617FD92C"),
           fromHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        },
        {
           32,
           fromHex("7FC5237896674E8603C1E9B03F8B4BA3AB5B7C592C3FC3D361EDD12586B20FE3"),
           fromHex("3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A29282726252423222120"),
           fromHex("1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100"),
        },
    }

    for i, test := range tests {
        c, err := NewCipher256_256(test.key)
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp := make([]byte, len(test.pt))
        c.Encrypt(tmp, test.pt)

        if !bytes.Equal(tmp, test.ct) {
            t.Errorf("[%d] Check error: got %x, want %x", i, tmp, test.ct)
        }

        // ===========

        c2, err := NewCipher256_256(test.key)
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp2 := make([]byte, len(test.ct))
        c2.Decrypt(tmp2, test.ct)

        if !bytes.Equal(tmp2, test.pt) {
            t.Errorf("[%d] Check Decrypt error: got %x, want %x", i, tmp2, test.pt)
        }
    }
}

func Test_Check128_256(t *testing.T) {
   tests := []testData{
        {
           32,
           fromHex("202122232425262728292A2B2C2D2E2F"),
           fromHex("58EC3E091000158A1148F7166F334F14"),
           fromHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        },
        {
           32,
           fromHex("F36DB456CEFDDFE1B45B5F7030CAD996"),
           fromHex("2F2E2D2C2B2A29282726252423222120"),
           fromHex("1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100"),
        },
    }

    for i, test := range tests {
        c, err := NewCipher128_256(test.key)
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp := make([]byte, len(test.pt))
        c.Encrypt(tmp, test.pt)

        if !bytes.Equal(tmp, test.ct) {
            t.Errorf("[%d] Check error: got %x, want %x", i, tmp, test.ct)
        }

        // ===========

        c2, err := NewCipher128_256(test.key)
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp2 := make([]byte, len(test.ct))
        c2.Decrypt(tmp2, test.ct)

        if !bytes.Equal(tmp2, test.pt) {
            t.Errorf("[%d] Check Decrypt error: got %x, want %x", i, tmp2, test.pt)
        }
    }
}

func Test_Check128_128(t *testing.T) {
   tests := []testData{
        {
           16,
           fromHex("101112131415161718191A1B1C1D1E1F"),
           fromHex("81BF1C7D779BAC20E1C9EA39B4D2AD06"),
           fromHex("000102030405060708090A0B0C0D0E0F"),
        },
        {
           16,
           fromHex("7291EF2B470CC7846F09C2303973DAD7"),
           fromHex("1F1E1D1C1B1A19181716151413121110"),
           fromHex("0F0E0D0C0B0A09080706050403020100"),
        },
    }

    for i, test := range tests {
        c, err := NewCipher128_128(test.key)
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp := make([]byte, len(test.pt))
        c.Encrypt(tmp, test.pt)

        if !bytes.Equal(tmp, test.ct) {
            t.Errorf("[%d] Check error: got %x, want %x", i, tmp, test.ct)
        }

        // ===========

        c2, err := NewCipher128_128(test.key)
        if err != nil {
            t.Fatal(err.Error())
        }

        tmp2 := make([]byte, len(test.ct))
        c2.Decrypt(tmp2, test.ct)

        if !bytes.Equal(tmp2, test.pt) {
            t.Errorf("[%d] Check Decrypt error: got %x, want %x", i, tmp2, test.pt)
        }
    }
}
