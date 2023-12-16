package zuc

import (
    "bytes"
    "testing"
    "math/rand"
)

func Test_Zuc(t *testing.T) {
    key := []byte("test-passg5tyhu8")
    iv := []byte("test-passg5tyhu8")

    in := []byte("test-passg5tyhu8")

    s := NewZucState(key, iv)

    out := make([]byte, len(in))
    s.Encrypt(out, in)

    if len(out) == 0 {
        t.Error("Zuc make error")
    }

    // ===========

    s2 := NewZucState(key, iv)

    out2 := make([]byte, len(in))
    s2.Encrypt(out2, out)

    if len(out) == 0 {
        t.Error("Zuc make 2 error")
    }

    if string(out2) != string(in) {
        t.Error("Zuc Decrypt error")
    }
}

func Test_Cipher(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 5000

    var encrypted [56]byte
    var decrypted [56]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 16)
        random.Read(key)
        iv := make([]byte, 16)
        random.Read(key)
        value := make([]byte, 56)
        random.Read(value)

        cipher1, err := NewCipher(key, iv)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.XORKeyStream(encrypted[:], value)

        cipher2, err := NewCipher(key, iv)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.XORKeyStream(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}
