package safer

import (
    "bytes"
    "testing"
    "math/rand"
)

func Test_KCipher_Key8(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 500

    var encrypted [8]byte
    var decrypted [8]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 8)
        random.Read(key)
        value := make([]byte, 8)
        random.Read(value)

        c1, err := NewKCipher(key, 6)
        if err != nil {
            t.Fatal(err.Error())
        }

        c1.Encrypt(encrypted[:], value)

        // ==========

        c2, err := NewKCipher(key, 6)
        if err != nil {
            t.Fatal(err.Error())
        }

        c2.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_KCipher_Key16(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 500

    var encrypted [8]byte
    var decrypted [8]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 16)
        random.Read(key)
        value := make([]byte, 8)
        random.Read(value)

        c1, err := NewKCipher(key, 6)
        if err != nil {
            t.Fatal(err.Error())
        }

        c1.Encrypt(encrypted[:], value)

        // ==========

        c2, err := NewKCipher(key, 6)
        if err != nil {
            t.Fatal(err.Error())
        }

        c2.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_SKCipher_Key8(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 500

    var encrypted [8]byte
    var decrypted [8]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 8)
        random.Read(key)
        value := make([]byte, 8)
        random.Read(value)

        c1, err := NewSKCipher(key, 6)
        if err != nil {
            t.Fatal(err.Error())
        }

        c1.Encrypt(encrypted[:], value)

        // ==========

        c2, err := NewSKCipher(key, 6)
        if err != nil {
            t.Fatal(err.Error())
        }

        c2.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_SKCipher_Key16(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 500

    var encrypted [8]byte
    var decrypted [8]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 16)
        random.Read(key)
        value := make([]byte, 8)
        random.Read(value)

        c1, err := NewSKCipher(key, 6)
        if err != nil {
            t.Fatal(err.Error())
        }

        c1.Encrypt(encrypted[:], value)

        // ==========

        c2, err := NewSKCipher(key, 6)
        if err != nil {
            t.Fatal(err.Error())
        }

        c2.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

func Test_K64_Check(t *testing.T) {
    var k64_pt  = []uint8{ 1, 2, 3, 4, 5, 6, 7, 8 }
    var k64_key = []uint8{ 8, 7, 6, 5, 4, 3, 2, 1 }
    var k64_ct  = []uint8{ 200, 242, 156, 221, 135, 120, 62, 217 }

    var encrypted [8]byte
    var decrypted [8]byte

    c1, err := NewKCipher(k64_key, 6)
    if err != nil {
        t.Fatal(err.Error())
    }

    c1.Encrypt(encrypted[:], k64_pt)

    if !bytes.Equal(encrypted[:], k64_ct) {
        t.Errorf("encryption failed: % 02x != % 02x\n", encrypted, k64_ct)
    }

    // ==========

    c2, err := NewKCipher(k64_key, 6)
    if err != nil {
        t.Fatal(err.Error())
    }

    c2.Decrypt(decrypted[:], k64_ct)

    if !bytes.Equal(decrypted[:], k64_pt[:]) {
        t.Errorf("decryption failed: % 02x != % 02x\n", decrypted, k64_pt)
    }
}

func Test_SK64_Check(t *testing.T) {
    var sk64_pt  = []uint8{ 1, 2, 3, 4, 5, 6, 7, 8 }
    var sk64_key = []uint8{ 1, 2, 3, 4, 5, 6, 7, 8 }
    var sk64_ct  = []uint8{ 95, 206, 155, 162, 5, 132, 56, 199 }

    var encrypted [8]byte
    var decrypted [8]byte

    c1, err := NewSKCipher(sk64_key, 6)
    if err != nil {
        t.Fatal(err.Error())
    }

    c1.Encrypt(encrypted[:], sk64_pt)

    if !bytes.Equal(encrypted[:], sk64_ct) {
        t.Errorf("encryption failed: % 02x != % 02x\n", encrypted, sk64_ct)
    }

    // ==========

    c2, err := NewSKCipher(sk64_key, 6)
    if err != nil {
        t.Fatal(err.Error())
    }

    c2.Decrypt(decrypted[:], sk64_ct)

    if !bytes.Equal(decrypted[:], sk64_pt[:]) {
        t.Errorf("decryption failed: % 02x != % 02x\n", decrypted, sk64_pt)
    }
}

func Test_SK128_Check(t *testing.T) {
    var sk128_pt  = []uint8{ 1, 2, 3, 4, 5, 6, 7, 8 }
    var sk128_key = []uint8{ 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0 }
    var sk128_ct  = []uint8{ 255, 120, 17, 228, 179, 167, 46, 113 }

    var encrypted [8]byte
    var decrypted [8]byte

    c1, err := NewSKCipher(sk128_key, 0)
    if err != nil {
        t.Fatal(err.Error())
    }

    c1.Encrypt(encrypted[:], sk128_pt)

    if !bytes.Equal(encrypted[:], sk128_ct) {
        t.Errorf("encryption failed: % 02x != % 02x\n", encrypted, sk128_ct)
    }

    // ==========

    c2, err := NewSKCipher(sk128_key, 0)
    if err != nil {
        t.Fatal(err.Error())
    }

    c2.Decrypt(decrypted[:], sk128_ct)

    if !bytes.Equal(decrypted[:], sk128_pt[:]) {
        t.Errorf("decryption failed: % 02x != % 02x\n", decrypted, sk128_pt)
    }
}
