package kupyna

import (
    "fmt"
    "testing"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func Test_Hash256(t *testing.T) {
    msg := []byte("test-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-data")

    h := New256()
    h.Write(msg)
    dst := h.Sum(nil)

    if len(dst) == 0 {
        t.Error("Hash make error")
    }
}

func Test_Hash512(t *testing.T) {
    msg := []byte("test-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-data")

    h := New512()
    h.Write(msg)
    dst := h.Sum(nil)

    if len(dst) == 0 {
        t.Error("Hash make error")
    }
}

func Test_Hash384(t *testing.T) {
    msg := []byte("test-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-data")

    h := New384()
    h.Write(msg)
    dst := h.Sum(nil)

    if len(dst) == 0 {
        t.Error("Hash make error")
    }
}

func Test_Hash256_Check(t *testing.T) {
    msg := []byte("012345678901234567890123456789012345678901234567890123456789012")

    h := New256()
    h.Write(msg)
    dst := h.Sum(nil)

    check := "5458da58f28e137100d564c6ea201356ae31c25f001e07e5c13090edd353a18f"

    if fmt.Sprintf("%x", dst) != check {
        t.Errorf("fail, got %x, want %s", dst, check)
    }
}

func Test_Hash512_Check(t *testing.T) {
    msg := []byte("012345678901234567890123456789012345678901234567890123456789012")

    h := New512()
    h.Write(msg)
    dst := h.Sum(nil)

    check := "9dc29544cd5f184cf5cfe0ccc9ab895c3a7cebff36805eba4468cfe8cb33c68fc57b61ef61d8ac65629eb3291d62bc7efb98aa422b2a2aa9d8fb236634d49aa9"

    if fmt.Sprintf("%x", dst) != check {
        t.Errorf("fail, got %x, want %s", dst, check)
    }
}

func Test_Hash384_Check(t *testing.T) {
    msg := []byte("012345678901234567890123456789012345678901234567890123456789012")

    h := New384()
    h.Write(msg)
    dst := h.Sum(nil)

    check := "3a7cebff36805eba4468cfe8cb33c68fc57b61ef61d8ac65629eb3291d62bc7efb98aa422b2a2aa9d8fb236634d49aa9"

    if fmt.Sprintf("%x", dst) != check {
        t.Errorf("fail, got %x, want %s", dst, check)
    }
}

func Test_Kmac256_Check(t *testing.T) {
    key := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    msg := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"

    k := fromHex(key)
    m := fromHex(msg)

    h, err := NewKmac256(k[:32])
    if err != nil {
        t.Fatal(err)
    }

    h.Write(m)
    dst := h.Sum(nil)

    check := "a0b5d5bcf95d75a809b05a018874b434194b618435c7fd0901d1d234b5e6b0db"

    if fmt.Sprintf("%x", dst) != check {
        t.Errorf("fail, got %x, want %s", dst, check)
    }
}

func Test_Kmac384_Check(t *testing.T) {
    key := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    msg := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"

    k := fromHex(key)
    m := fromHex(msg)

    h, err := NewKmac384(k[:48])
    if err != nil {
        t.Fatal(err)
    }

    h.Write(m)
    dst := h.Sum(nil)

    check := "5a27925090d579ea756f57c4318b0bfea639a95798dbe2915c7aefb90f082bbea49b423a73e304ac410b9ef6aefe5409"

    if fmt.Sprintf("%x", dst) != check {
        t.Errorf("fail, got %x, want %s", dst, check)
    }
}

func Test_Kmac512_Check(t *testing.T) {
    key := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    msg := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"

    k := fromHex(key)
    m := fromHex(msg)

    h, err := NewKmac512(k[:64])
    if err != nil {
        t.Fatal(err)
    }

    h.Write(m)
    dst := h.Sum(nil)

    check := "1ae8a63bfbdeb4f4b0e739827ca2bc6a87f7a7e92187d926d19b9bcf4d59d78fb9a0d05a14c0ee0c9a113a681b7c8c6515c960d302af2db5ddcfe9b248c4cd8a"

    if fmt.Sprintf("%x", dst) != check {
        t.Errorf("fail, got %x, want %s", dst, check)
    }
}

type testKmacData struct {
    key   []byte
    klen  int
    msg   []byte
    check string
}

func Test_Kmac_Check(t *testing.T) {
    tests := []testKmacData{
        {
            key:   fromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            klen:  32,
            msg:   fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
            check: "a0b5d5bcf95d75a809b05a018874b434194b618435c7fd0901d1d234b5e6b0db",
        },
        {
            key:   fromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            klen:  48,
            msg:   fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
            check: "5a27925090d579ea756f57c4318b0bfea639a95798dbe2915c7aefb90f082bbea49b423a73e304ac410b9ef6aefe5409",
        },
        {
            key:   fromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            klen:  64,
            msg:   fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
            check: "1ae8a63bfbdeb4f4b0e739827ca2bc6a87f7a7e92187d926d19b9bcf4d59d78fb9a0d05a14c0ee0c9a113a681b7c8c6515c960d302af2db5ddcfe9b248c4cd8a",
        },
    }

    for i, td := range tests {
        h, err := NewKmac(td.key[:td.klen])
        if err != nil {
            t.Fatal(err)
        }

        h.Write(td.msg)
        sum := h.Sum(nil)

        if fmt.Sprintf("%x", sum) != td.check {
            t.Errorf("[%d] fail, got %x, want %s", i, sum, td.check)
        }
    }
}

func Test_Kmac_Fail(t *testing.T) {
    key := []byte("123123")

    _, err := NewKmac(key)
    if err == nil {
        t.Error("NewKmac should return error")
    }
}
