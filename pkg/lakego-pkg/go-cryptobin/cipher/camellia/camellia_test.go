package camellia

import (
    "bytes"
    "testing"
)

// Test vectors from http://tools.ietf.org/html/rfc3713
var camelliaTests = []struct {
    key    []byte
    plain  []byte
    cipher []byte
}{
    {
        []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
        []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
        []byte{0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73, 0x08, 0x57, 0x06, 0x56, 0x48, 0xea, 0xbe, 0x43},
    },

    // 192-bit key
    {
        []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},
        []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
        []byte{0xb4, 0x99, 0x34, 0x01, 0xb3, 0xe9, 0x96, 0xf8, 0x4e, 0xe5, 0xce, 0xe7, 0xd7, 0x9b, 0x09, 0xb9},
    },

    //256-bit key
    {
        []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
        []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
        []byte{0x9a, 0xcc, 0x23, 0x7d, 0xff, 0x16, 0xd7, 0x6c, 0x20, 0xef, 0x7c, 0x91, 0x9e, 0x3a, 0x75, 0x09},
    },
}

/*
func TestRot(t  *testing.T) {

    return

    var u8 = uint8(1)
    for i := 0; i < 8; i++ {
        fmt.Printf("1: %d: %08b\n", i, rotl8(1, uint(i)))
        u8 = rotl8(u8, 1)
        fmt.Printf("u: %d: %08b\n", i+1, u8)
    }

    var u32 = uint32(1)
    for i := 0; i < 32; i++ {
        fmt.Printf("1: %02d: %032b\n", i, rotl32(1, uint(i)))
        u32 = rotl32(u32, 1)
        fmt.Printf("u: %02d: %032b\n", i+1, u32)
    }

    var u128 [2]uint64
    u128[1] = 1
    for i := 0; i < 128; i++ {
        var one  = [2]uint64{0, 1}
        u0, u1 := rotl128(one, uint(i))
        fmt.Printf("1: %03d: %064b %064b\n", i, u0, u1)
        u128[0], u128[1] = rotl128(u128, 1)
        fmt.Printf("u: %03d: %064b %064b\n", i+1, u128[0], u128[1])
    }
}
*/

func TestCamellia(t *testing.T) {

    for _, tt := range camelliaTests {
        c, _ := New(tt.key)
        var b [16]byte
        c.Encrypt(b[:], tt.plain)
        if !bytes.Equal(b[:], tt.cipher) {
            t.Errorf("encrypt failed:\ngot : % 02x\nwant: % 02x", b, tt.cipher)
        }

        c.Decrypt(b[:], tt.cipher)
        if !bytes.Equal(b[:], tt.plain) {
            t.Errorf("decrypt failed:\ngot : % 02x\nwant: % 02x", b, tt.plain)
        }
    }
}