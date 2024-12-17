package aria

import (
    "fmt"
    "bytes"
    "testing"
    "crypto/aes"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func TestInvalidKeySize(t *testing.T) {
    for _, k := range []int{0, 1, 15, 31} {
        _, err := NewCipher(make([]byte, k))
        if err == nil {
            t.Errorf("expected an error for key size %d, got no error", k)
        }
        if _, ok := err.(KeySizeError); !ok {
            t.Errorf("expected KeySizeError, got %v", err)
        }
        if msg := err.Error(); msg != fmt.Sprintf("go-cryptobin/aria: invalid key size %d", k) {
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
           fromHex("00112233445566778899aabbccddeeff"),
           fromHex("f92bd7c79fb72e2f2b8f80c1972d24fc"),
           fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        },
        {
           32,
           fromHex("11111111aaaaaaaa11111111bbbbbbbb"),
           fromHex("58a875e6044ad7fffa4f58420f7f442d"),
           fromHex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
        },

        {
           24,
           fromHex("00112233445566778899aabbccddeeff"),
           fromHex("26449c1805dbe7aa25a468ce263a9e79"),
           fromHex("000102030405060708090a0b0c0d0e0f1011121314151617"),
        },
        {
           24,
           fromHex("33333333cccccccc33333333dddddddd"),
           fromHex("f1f7188734863d7b8b6ede5a5b2f06a0"),
           fromHex("00112233445566778899aabbccddeeff0011223344556677"),
        },

        {
           16,
           fromHex("11111111aaaaaaaa11111111bbbbbbbb"),
           fromHex("c6ecd08e22c30abdb215cf74e2075e6e"),
           fromHex("00112233445566778899aabbccddeeff"),
        },
        {
           16,
           fromHex("55555555aaaaaaaa55555555bbbbbbbb"),
           fromHex("086953f752cc1e46c7c794ae85537dca"),
           fromHex("00112233445566778899aabbccddeeff"),
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
