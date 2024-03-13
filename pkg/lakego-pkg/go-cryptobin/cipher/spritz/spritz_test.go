package spritz

import (
    "bytes"
    "testing"
)

func TestOutput(t *testing.T) {
    var tests = []struct {
        key    string
        output []byte
    }{
        {"ABC", []byte{0x77, 0x9a, 0x8e, 0x01, 0xf9, 0xe9, 0xcb, 0xc0}},
        {"spam", []byte{0xf0, 0x60, 0x9a, 0x1d, 0xf1, 0x43, 0xce, 0xbf}},
        {"arcfour", []byte{0x1a, 0xfa, 0x8b, 0x5e, 0xe3, 0x37, 0xdb, 0xc7}},
    }

    for _, tt := range tests {
        var c spritzCipher
        c.keySetup([]byte(tt.key))

        for i, b := range tt.output {
            if v := c.drip(); v != b {
                t.Errorf("key %q byte %d failed: got %x, want %x\n", tt.key, i, v, b)
            }
        }
    }
}

func TestHash(t *testing.T) {

    var tests = []struct {
        key    string
        output []byte
    }{
        // PDF only provides first 8 bytes for a 32-byte hash
        {"ABC", []byte{0x02, 0x8f, 0xa2, 0xb4, 0x8b, 0x93, 0x4a, 0x18}},
        {"spam", []byte{0xac, 0xbb, 0xa0, 0x81, 0x3f, 0x30, 0x0d, 0x3a}},
        {"arcfour", []byte{0xff, 0x8c, 0xf2, 0x68, 0x09, 0x4c, 0x87, 0xb9}},
    }

    for _, tt := range tests {
        if h := Hash([]byte(tt.key), 32); !bytes.Equal(h[:8], tt.output) {
            t.Errorf("Hash(%q)=%x, want %x", tt.key, h[:8], tt.output)
        }
    }
}

func TestRoundtrip(t *testing.T) {

    key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
    iv := []byte{0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

    str := []byte("the magic words are squeamish ossifrage")

    c1, _ := NewCipher(key)
    ctxt := make([]byte, len(str))
    c1.Encrypt(ctxt, str)

    c11, _ := NewCipher(key)
    ptxt := make([]byte, len(str))
    c11.Decrypt(ptxt, ctxt)

    if !bytes.Equal(ptxt, str) {
        t.Errorf("Decrypt(key,Encrypt(key,str)) != str)")
    }

    c2, _ := NewCipherWithIV(key, iv)
    c2.Encrypt(ctxt, str)

    c21, _ := NewCipherWithIV(key, iv)
    c21.Decrypt(ptxt, ctxt)

    if !bytes.Equal(ptxt, str) {
        t.Errorf("DecryptWithIV(key,EncryptWithIV(key,str)) != str)")
    }
}
