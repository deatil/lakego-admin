package twine

import (
    "bytes"
    "testing"
)

var tests = []struct {
    key    []byte
    plain  []byte
    cipher []byte
}{
    // http://jpn.nec.com/rd/crl/code/research/image/twine_SAC_full_v4.pdf
    {
        []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
        []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
        []byte{0x7c, 0x1f, 0x0f, 0x80, 0xb1, 0xdf, 0x9c, 0x28},
    },
    {

        []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
        []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
        []byte{0x97, 0x9F, 0xF9, 0xB3, 0x79, 0xB5, 0xA9, 0xB8},
    },
}

func Test_Check(t *testing.T) {

    for _, tst := range tests {

        c, _ := NewCipher(tst.key)

        var ct [8]byte

        c.Encrypt(ct[:], tst.plain[:])

        if !bytes.Equal(ct[:], tst.cipher) {
            t.Errorf("encrypt failed:\ngot : % 02x\nwant: % 02x", ct[:], tst.cipher)
        }

        var p [8]byte

        c.Decrypt(p[:], ct[:])

        if !bytes.Equal(p[:], tst.plain) {
            t.Errorf("decrypt failed:\ngot : % 02x\nwant: % 02x", p[:], tst.plain)
        }
    }
}
