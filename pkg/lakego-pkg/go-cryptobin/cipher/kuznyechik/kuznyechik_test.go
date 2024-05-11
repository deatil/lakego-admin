package kuznyechik

import (
    "bytes"
    "testing"
    "math/rand"
)

func Test_Kuznyechik(t *testing.T) {
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

        if bytes.Equal(encrypted[:], value[:]) {
            t.Errorf("fail: encrypted equal value\n")
        }

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

func Test_Check(t *testing.T) {
    var (
        key []byte = []byte{
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        }
        pt [BlockSize]byte = [BlockSize]byte{
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        }
        ct [BlockSize]byte = [BlockSize]byte{
            0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30,
            0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd,
        }
    )

    {
        c, _ := NewCipher(key)
        dst := make([]byte, BlockSize)
        c.Encrypt(dst, pt[:])
        if !bytes.Equal(dst, ct[:]) {
            t.Errorf("fail, got %x, want %x", dst, ct)
        }
    }

    {
        c, _ := NewCipher(key)
        dst := make([]byte, BlockSize)
        c.Decrypt(dst, ct[:])
        if !bytes.Equal(dst, pt[:]) {
            t.Errorf("fail, got %x, want %x", dst, pt)
        }
    }

}
