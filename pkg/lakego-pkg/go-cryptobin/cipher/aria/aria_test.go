package aria

import (
    "fmt"
    "bytes"
    "testing"
    "crypto/aes"
)

func TestInvalidKeySize(t *testing.T) {
    for _, k := range []int{0, 1, 15, 31} {
        _, err := NewCipher(make([]byte, k))
        if err == nil {
            t.Errorf("expected an error for key size %d, got no error", k)
        }
        if _, ok := err.(KeySizeError); !ok {
            t.Errorf("expected KeySizeError, got %v", err)
        }
        if msg := err.Error(); msg != fmt.Sprintf("cryptobin/aria: invalid key size %d", k) {
            t.Errorf("wrong error message %s", msg)
        }
    }
}

func TestBlockSize(t *testing.T) {
    for _, k := range []int{16, 24, 32} {
        key := make([]byte, k)
        block, err := NewCipher(key)
        if err != nil {
            t.Fatal(err)
        }
        if s := block.BlockSize(); s != 16 {
            t.Errorf("wrong block size %d, expected 16", s)
        }
    }
}

func TestBadBlock(t *testing.T) {
    type testcase struct {
        dst, src []byte
    }

    b := make([]byte, 32)

    for _, k := range []int{16, 24, 32} {
        for _, tc := range []testcase{
            {dst: make([]byte, 16), src: make([]byte, 1)},
            {dst: make([]byte, 1), src: make([]byte, 16)},
            {dst: b, src: b[1:]},
        } {
            block, err := NewCipher(make([]byte, k))
            if err != nil {
                t.Fatal(err)
            }

            func(k int, tc testcase) {
                defer func() {
                    if r := recover(); r == nil {
                        t.Error("expected panic, has no panic")
                    }
                }()
                block.Encrypt(tc.dst, tc.src)
            }(k, tc)

            func(k int, tc testcase) {
                defer func() {
                    if r := recover(); r == nil {
                        t.Error("expected panic, has no panic")
                    }
                }()
                block.Decrypt(tc.dst, tc.src)
            }(k, tc)
        }
    }
}

func TestEncryptAndDecrypt(t *testing.T) {
    key := []byte("0123456789abcdef")
    input := []byte("fedcba9876543210")

    block, err := NewCipher(key)
    if err != nil {
        t.Fatal(err)
    }

    cipher := make([]byte, 16)
    block.Encrypt(cipher, input)
    t.Logf("cipher: %x", cipher)

    plain := make([]byte, 16)
    block.Decrypt(plain, cipher)
    t.Logf("decrypted: %x", plain)

    if !bytes.Equal(input, plain) {
        t.Errorf("input(%x) != decrypted(%x)", input, plain)
    }
}

func BenchmarkAES128(b *testing.B) { benchmarkAES(b, 16) }
func BenchmarkAES192(b *testing.B) { benchmarkAES(b, 24) }
func BenchmarkAES256(b *testing.B) { benchmarkAES(b, 32) }

func BenchmarkARIA128(b *testing.B) { benchmarkARIA(b, 16) }
func BenchmarkARIA192(b *testing.B) { benchmarkARIA(b, 24) }
func BenchmarkARIA256(b *testing.B) { benchmarkARIA(b, 32) }

func benchmarkAES(b *testing.B, k int) {
    b.StopTimer()
    key := make([]byte, k)
    input := make([]byte, 16)
    block, err := aes.NewCipher(key)
    if err != nil {
        b.Fatal(err)
    }
    cipher := make([]byte, 16)
    b.StartTimer()
    for i := 0; i < b.N; i++ {
        block.Encrypt(cipher, input)
    }
}

func benchmarkARIA(b *testing.B, k int) {
    b.StopTimer()
    key := make([]byte, k)
    input := make([]byte, 16)
    block, err := NewCipher(key)
    if err != nil {
        b.Fatal(err)
    }
    cipher := make([]byte, 16)
    b.StartTimer()
    for i := 0; i < b.N; i++ {
        block.Encrypt(cipher, input)
    }
}
