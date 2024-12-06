package mac

import (
    "bytes"
    "crypto/aes"
    "encoding/hex"
    "testing"

    "github.com/deatil/go-cryptobin/cipher/sm4"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func TestCBCMAC(t *testing.T) {
    // Test vectors from GB/T 15821.1-2020 Appendix B.
    cases := []struct {
        key []byte
        src []byte
        tag []byte
    }{
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            nil,
            []byte{0x8c, 0x33, 0x8e, 0x5a, 0x27, 0xe3, 0x49, 0xbe, 0xae, 0x39, 0x21, 0x4f, 0xed, 0xa9, 0x70, 0x99},
        },
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            []byte("This is the test message for mac"),
            []byte{0x4b, 0x65, 0x53, 0xaf, 0x3c, 0x4e, 0x27, 0x44, 0x84, 0x12, 0x31, 0x5a, 0xc7, 0x84, 0x95, 0x35},
        },
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            []byte("This is the test message "),
            []byte{0x42, 0x1a, 0xd1, 0x69, 0x0a, 0xa1, 0x52, 0xe2, 0x84, 0x6f, 0xa2, 0xa5, 0xd8, 0x34, 0x45, 0xa9},
        },
    }

    for i, c := range cases {
        block, err := sm4.NewCipher(c.key)
        if err != nil {
            t.Errorf("#%d: failed to create cipher: %v", i, err)
        }

        mac := NewCBCMAC(block, len(c.tag))
        tag := mac.MAC(c.src)

        if !bytes.Equal(tag, c.tag) {
            t.Errorf("#%d: expect tag %x, got %x", i, c.tag, tag)
        }
    }
}

func TestEMAC(t *testing.T) {
    // Test vectors from GB/T 15821.1-2020 Appendix B.
    cases := []struct {
        key1 []byte
        key2 []byte
        src  []byte
        tag  []byte
    }{
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            []byte{0x41, 0x49, 0xd2, 0xad, 0xed, 0x94, 0x56, 0x68, 0x1e, 0xc8, 0xb5, 0x11, 0xd9, 0xe7, 0xee, 0x04},
            nil,
            []byte{0x2c, 0xf6, 0xed, 0xf6, 0x3c, 0xce, 0x14, 0x44, 0x89, 0xea, 0xdd, 0xf0, 0x7b, 0x49, 0x38, 0xdb},
        },
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            []byte{0x41, 0x49, 0xd2, 0xad, 0xed, 0x94, 0x56, 0x68, 0x1e, 0xc8, 0xb5, 0x11, 0xd9, 0xe7, 0xee, 0x04},
            []byte("This is the test message for mac"),
            []byte{0xe4, 0x23, 0xe3, 0x55, 0x99, 0xaf, 0xd9, 0x48, 0xae, 0xc5, 0x0b, 0xde, 0xe8, 0x38, 0xe9, 0xea},
        },
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            []byte{0x41, 0x49, 0xd2, 0xad, 0xed, 0x94, 0x56, 0x68, 0x1e, 0xc8, 0xb5, 0x11, 0xd9, 0xe7, 0xee, 0x04},
            []byte("This is the test message "),
            []byte{0xf0, 0x26, 0x25, 0xce, 0xad, 0x00, 0x8d, 0x4e, 0xfb, 0xf3, 0xf0, 0xb2, 0xb0, 0xc2, 0xa7, 0x5b},
        },
    }

    for i, c := range cases {
        mac := NewEMAC(sm4.NewCipher, c.key1, c.key2, len(c.tag))
        tag := mac.MAC(c.src)

        if !bytes.Equal(tag, c.tag) {
            t.Errorf("#%d: expect tag %x, got %x", i, c.tag, tag)
        }
    }
}

func TestANSIRetailMAC(t *testing.T) {
    // Test vectors from GB/T 15821.1-2020 Appendix B.
    cases := []struct {
        key1 []byte
        key2 []byte
        src  []byte
        tag  []byte
    }{
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            []byte{0x41, 0x49, 0xd2, 0xad, 0xed, 0x94, 0x56, 0x68, 0x1e, 0xc8, 0xb5, 0x11, 0xd9, 0xe7, 0xee, 0x04},
            nil,
            []byte{0xb4, 0x73, 0x6b, 0xe9, 0xa1, 0x74, 0xfa, 0xa3, 0x4d, 0xb1, 0xe9, 0xf1, 0xda, 0xcd, 0x5d, 0x62},
        },
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            []byte{0x41, 0x49, 0xd2, 0xad, 0xed, 0x94, 0x56, 0x68, 0x1e, 0xc8, 0xb5, 0x11, 0xd9, 0xe7, 0xee, 0x04},
            []byte("This is the test message for mac"),
            []byte{0x51, 0xe9, 0x92, 0x8c, 0x22, 0x38, 0x33, 0x0c, 0x32, 0x31, 0xb8, 0x75, 0x2a, 0x9a, 0xfd, 0x7f},
        },
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            []byte{0x41, 0x49, 0xd2, 0xad, 0xed, 0x94, 0x56, 0x68, 0x1e, 0xc8, 0xb5, 0x11, 0xd9, 0xe7, 0xee, 0x04},
            []byte("This is the test message "),
            []byte{0x19, 0x72, 0x47, 0x22, 0x9c, 0xe9, 0xd7, 0xb6, 0xae, 0x40, 0x5b, 0xf8, 0x85, 0xb2, 0x70, 0x57},
        },
    }

    for i, c := range cases {
        mac := NewANSIRetailMAC(sm4.NewCipher, c.key1, c.key2, len(c.tag))
        tag := mac.MAC(c.src)

        if !bytes.Equal(tag, c.tag) {
            t.Errorf("#%d: expect tag %x, got %x", i, c.tag, tag)
        }
    }
}

func TestMACDES(t *testing.T) {
    // Test vectors from GB/T 15821.1-2020 Appendix B.
    cases := []struct {
        key1 []byte
        key2 []byte
        src  []byte
        tag  []byte
    }{
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            []byte{0x41, 0x49, 0xd2, 0xad, 0xed, 0x94, 0x56, 0x68, 0x1e, 0xc8, 0xb5, 0x11, 0xd9, 0xe7, 0xee, 0x04},
            nil,
            []byte{0x0c, 0x56, 0x00, 0x96, 0xb6, 0x09, 0xed, 0x0e, 0xaa, 0x39, 0xaf, 0xd6, 0xe2, 0x66, 0x65, 0x11},
        },
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            []byte{0x41, 0x49, 0xd2, 0xad, 0xed, 0x94, 0x56, 0x68, 0x1e, 0xc8, 0xb5, 0x11, 0xd9, 0xe7, 0xee, 0x04},
            []byte("This is the test message for mac"),
            []byte{0x7e, 0x1a, 0x9a, 0x5e, 0x0e, 0xf0, 0x94, 0x7f, 0x25, 0xcb, 0x94, 0x85, 0x26, 0x1c, 0x98, 0x5c},
        },
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            []byte{0x41, 0x49, 0xd2, 0xad, 0xed, 0x94, 0x56, 0x68, 0x1e, 0xc8, 0xb5, 0x11, 0xd9, 0xe7, 0xee, 0x04},
            []byte("This is the test message "),
            []byte{0x94, 0x94, 0x76, 0xd3, 0x5f, 0x17, 0x26, 0x1e, 0x1f, 0xb8, 0xc4, 0x39, 0x6d, 0x62, 0xdc, 0x05},
        },
    }

    for i, c := range cases {
        mac := NewMACDES(sm4.NewCipher, c.key1, c.key2, 16)
        tag := mac.MAC(c.src)

        if !bytes.Equal(tag, c.tag) {
            t.Errorf("#%d: expect tag %x, got %x", i, c.tag, tag)
        }
    }
}

func TestCMAC(t *testing.T) {
    // Test vectors from GB/T 15821.1-2020 Appendix B.
    cases := []struct {
        key []byte
        src []byte
        tag []byte
    }{
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            nil,
            []byte{0x29, 0xe1, 0x54, 0x32, 0x2e, 0x5c, 0x7b, 0xd8, 0xee, 0x6a, 0x25, 0xba, 0x54, 0x9b, 0x24, 0xbc},
        },
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            []byte("This is the test message for mac"),
            []byte{0x69, 0x2c, 0x43, 0x71, 0x00, 0xf3, 0xb5, 0xee, 0x2b, 0x8a, 0xbc, 0xef, 0x37, 0x3d, 0x99, 0x0c},
        },
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            []byte("This is the test message "),
            []byte{0x47, 0x38, 0xa6, 0xc7, 0x60, 0xb2, 0x80, 0xfc, 0x0c, 0x8a, 0x8a, 0xf3, 0x88, 0x6e, 0x9f, 0x5d},
        },
    }
    for i, c := range cases {
        block, err := sm4.NewCipher(c.key)
        if err != nil {
            t.Errorf("#%d: failed to create cipher: %v", i, err)
        }

        mac := NewCMAC(block, 16)
        tag := mac.MAC(c.src)

        if !bytes.Equal(tag, c.tag) {
            t.Errorf("#%d: expect tag %x, got %x", i, c.tag, tag)
        }
    }
}

func TestLMAC(t *testing.T) {
    // Test vectors from GB/T 15821.1-2020 Appendix B.
    cases := []struct {
        key []byte
        src []byte
        tag []byte
    }{
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            nil,
            []byte{0xcd, 0x7e, 0xd2, 0x79, 0x64, 0xe2, 0x57, 0xc0, 0x77, 0xf0, 0x55, 0xf8, 0xee, 0x38, 0x3c, 0x3f},
        },

        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            []byte("This is the test message for mac"),
            []byte{0xa0, 0xc4, 0x65, 0xee, 0x58, 0x96, 0x97, 0x2f, 0x83, 0x37, 0xaa, 0x1f, 0x92, 0xc9, 0x9d, 0x10},
        },
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            []byte("This is the test message "),
            []byte{0x60, 0xdd, 0x95, 0x5e, 0xd0, 0xca, 0x3d, 0x7a, 0x64, 0x22, 0x71, 0x74, 0xdd, 0x98, 0xdd, 0x81},
        },
    }

    for i, c := range cases {
        mac := NewLMAC(sm4.NewCipher, c.key, 16)
        tag := mac.MAC(c.src)

        if !bytes.Equal(tag, c.tag) {
            t.Errorf("#%d: expect tag %x, got %x", i, c.tag, tag)
        }
    }
}

func TestTRCBCMAC(t *testing.T) {
    // Test vectors from GB/T 15821.1-2020 Appendix B.
    cases := []struct {
        key []byte
        src []byte
        tag []byte
    }{
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            nil,
            []byte{0xae, 0x39, 0x21, 0x4f, 0xed, 0xa9, 0x70, 0x99},
        },
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            []byte("This is the test message for mac"),
            []byte{0x16, 0xe0, 0x29, 0x04, 0xef, 0xb7, 0x65, 0xb7},
        },
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            []byte("This is the test message "),
            []byte{0x84, 0x6f, 0xa2, 0xa5, 0xd8, 0x34, 0x45, 0xa9},
        },
    }

    for i, c := range cases {
        block, err := sm4.NewCipher(c.key)
        if err != nil {
            t.Errorf("#%d: failed to create cipher: %v", i, err)
        }

        mac := NewTRCBCMAC(block, len(c.tag))
        tag := mac.MAC(c.src)

        if !bytes.Equal(tag, c.tag) {
            t.Errorf("#%d: expect tag %x, got %x", i, c.tag, tag)
        }
    }
}

func TestCBCRMAC(t *testing.T) {
    // Test vectors from GB/T 15821.1-2020 Appendix B.
    cases := []struct {
        key []byte
        src []byte
        tag []byte
    }{
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            nil,
            []byte{0x90, 0x9f, 0x5e, 0x6e, 0xd1, 0x55, 0x18, 0xc0, 0x12, 0x52, 0x30, 0x23, 0x83, 0xc6, 0x3e, 0x8c},
        },
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            []byte("This is the test message for mac"),
            []byte{0xe4, 0x0e, 0xd7, 0x9c, 0x31, 0x49, 0xa1, 0xc9, 0xd4, 0x2f, 0x04, 0xc4, 0x23, 0x04, 0x99, 0x35},
        },
        {
            []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
            []byte("This is the test message "),
            []byte{0xa9, 0x9d, 0x13, 0x01, 0x3e, 0x89, 0x2e, 0xe2, 0xc2, 0x5b, 0xe2, 0xda, 0xaa, 0x6c, 0x82, 0xe8},
        },
    }

    for i, c := range cases {
        block, err := sm4.NewCipher(c.key)
        if err != nil {
            t.Errorf("#%d: failed to create cipher: %v", i, err)
        }

        mac := NewCBCRMAC(block, 16)
        tag := mac.MAC(c.src)

        if !bytes.Equal(tag, c.tag) {
            t.Errorf("#%d: expect tag %x, got %x", i, c.tag, tag)
        }
    }
}

func TestMustPanic(t *testing.T) {
    t.Run("invalid size", func(t *testing.T) {
        key := make([]byte, 16)
        block, _ := sm4.NewCipher(key)
        cryptobin_test.MustPanic(t, "go-cryptobin/mac: invalid size", func() {
            NewCBCMAC(block, 0)
            NewCBCMAC(block, 17)
            NewEMAC(sm4.NewCipher, key, key, 0)
            NewEMAC(sm4.NewCipher, key, key, 17)
            NewANSIRetailMAC(sm4.NewCipher, key, key, 0)
            NewANSIRetailMAC(sm4.NewCipher, key, key, 17)
            NewMACDES(sm4.NewCipher, key, key, 0)
            NewMACDES(sm4.NewCipher, key, key, 17)
            NewCMAC(block, 0)
            NewCMAC(block, 17)
            NewLMAC(sm4.NewCipher, key, 0)
            NewLMAC(sm4.NewCipher, key, 17)
            NewTRCBCMAC(block, 0)
            NewTRCBCMAC(block, 17)
            NewCBCRMAC(block, 0)
            NewCBCRMAC(block, 17)
        })
    })

    t.Run("invalid key size", func(t *testing.T) {
        key := make([]byte, 16)
        cryptobin_test.MustPanic(t, "go-cryptobin/mac: invalid size", func() {
            NewEMAC(sm4.NewCipher, key[:15], key, 8)
            NewEMAC(sm4.NewCipher, key, key[:15], 8)
            NewANSIRetailMAC(sm4.NewCipher, key[:15], key, 8)
            NewANSIRetailMAC(sm4.NewCipher, key, key[:15], 8)
            NewMACDES(sm4.NewCipher, key[:15], key, 8)
            NewMACDES(sm4.NewCipher, key, key[:15], 8)
            NewLMAC(sm4.NewCipher, key[:15], 8)
        })
    })

}

func fromHex(s string) []byte {
    b, err := hex.DecodeString(s)
    if err != nil {
        panic(err)
    }

    return b
}

// Test vectors for CMAC-AES from NIST
// http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf
// Appendix D
var testVectors = []struct {
    key, msg, hash string
    tagsize        int
}{
    // AES-128 vectors
    {
        key:     "2b7e151628aed2a6abf7158809cf4f3c",
        msg:     "",
        hash:    "bb1d6929e95937287fa37d129b756746",
        tagsize: 16,
    },
    {
        key:     "2b7e151628aed2a6abf7158809cf4f3c",
        msg:     "6bc1bee22e409f96e93d7e117393172a",
        hash:    "070a16b46b4d4144f79bdd9dd04a287c",
        tagsize: 16,
    },
    {
        key:     "2b7e151628aed2a6abf7158809cf4f3c",
        msg:     "6bc1bee22e409f96e93d7e117393172aae2d8a57",
        hash:    "7d85449ea6ea19c823a7bf78837dfade",
        tagsize: 16,
    },
    {
        key: "2b7e151628aed2a6abf7158809cf4f3c",
        msg: "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411e5fbc1191a0a52ef" +
            "f69f2445df4f9b17ad2b417be66c3710",
        hash:    "51f0bebf7e3b9d92fc49741779363cfe",
        tagsize: 16,
    },
    {
        key: "2b7e151628aed2a6abf7158809cf4f3c",
        msg: "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411",
        hash:    "dfa66747de9ae63030ca32611497c827",
        tagsize: 16,
    },
    {
        key: "2b7e151628aed2a6abf7158809cf4f3c",
        msg: "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411",
        hash:    "dfa66747de9ae63030ca32611497c827",
        tagsize: 16,
    },
    {
        key: "2b7e151628aed2a6abf7158809cf4f3c",
        msg: "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411",
        hash:    "dfa66747de9ae63030ca3261",
        tagsize: 12,
    },
    // AES-256 vectors
    {
        key: "603deb1015ca71be2b73aef0857d7781" +
            "1f352c073b6108d72d9810a30914dff4",
        msg:     "",
        hash:    "028962f61b7bf89efc6b551f4667d983",
        tagsize: 16,
    },
    {
        key: "603deb1015ca71be2b73aef0857d7781" +
            "1f352c073b6108d72d9810a30914dff4",
        msg:     "6bc1bee22e409f96e93d7e117393172a",
        hash:    "28a7023f452e8f82bd4bf28d8c37c35c",
        tagsize: 16,
    },
    {
        key: "603deb1015ca71be2b73aef0857d7781" +
            "1f352c073b6108d72d9810a30914dff4",
        msg:     "6bc1bee22e409f96e93d7e117393172aae2d8a57",
        hash:    "156727dc0878944a023c1fe03bad6d93",
        tagsize: 16,
    },
    {
        key: "603deb1015ca71be2b73aef0857d7781" +
            "1f352c073b6108d72d9810a30914dff4",
        msg: "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411e5fbc1191a0a52ef" +
            "f69f2445df4f9b17ad2b417be66c3710",
        hash:    "e1992190549f6ed5696a2c056c315410",
        tagsize: 16,
    },
    {
        key: "603deb1015ca71be2b73aef0857d7781" +
            "1f352c073b6108d72d9810a30914dff4",
        msg: "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411",
        hash:    "aaf3d8f1de5640c232f5b169b9c911e6",
        tagsize: 16,
    },
    {
        key: "603deb1015ca71be2b73aef0857d7781" +
            "1f352c073b6108d72d9810a30914dff4",
        msg: "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411",
        hash:    "aaf3d8f1de5640c232f5b169",
        tagsize: 12,
    },
}

func TestCMACAES(t *testing.T) {
    for i, v := range testVectors {
        key := fromHex(v.key)
        msg := fromHex(v.msg)
        hash := fromHex(v.hash)

        block, err := aes.NewCipher(key)
        if err != nil {
            t.Errorf("#%d: failed to create cipher: %v", i, err)
        }

        mac := NewCMAC(block, v.tagsize)
        tag := mac.MAC(msg)

        if !bytes.Equal(tag, hash) {
            t.Errorf("#%d: expect tag %x, got %x", i, hash, tag)
        }
    }
}
