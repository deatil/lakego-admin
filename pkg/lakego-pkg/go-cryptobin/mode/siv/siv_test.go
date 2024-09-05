package siv

import (
    "bytes"
    "testing"
    "crypto/aes"
)

func Test_AEADAESCMACSIV(t *testing.T) {
    v := loadAESSIVExamples("aes_siv.tjson")[0]
    nonce := v.ad[0]

    n := len(v.key)
    macBlock, _ := aes.NewCipher(v.key[:n/2])
    ctrBlock, _ := aes.NewCipher(v.key[n/2:])

    c, err := NewCMAC(macBlock, ctrBlock, len(nonce))
    if err != nil {
        t.Fatal(err)
    }

    ct := c.Seal(nil, nonce, v.plaintext, nil)
    if !bytes.Equal(v.ciphertext, ct) {
        t.Errorf("Seal: expected: %x\ngot: %x", v.ciphertext, ct)
    }

    pt, err := c.Open(nil, nonce, ct, nil)
    if err != nil {
        t.Errorf("Open: %s", err)
    }

    if !bytes.Equal(v.plaintext, pt) {
        t.Errorf("Open: expected: %x\ngot: %x", v.plaintext, pt)
    }
}

func TestAEADAESPMACSIV(t *testing.T) {
    v := loadAESSIVExamples("aes_pmac_siv.tjson")[0]
    nonce := v.ad[0]

    n := len(v.key)
    macBlock, _ := aes.NewCipher(v.key[:n/2])
    ctrBlock, _ := aes.NewCipher(v.key[n/2:])

    c, err := NewPMAC(macBlock, ctrBlock, len(nonce))
    if err != nil {
        t.Fatal(err)
    }

    ct := c.Seal(nil, nonce, v.plaintext, nil)
    if !bytes.Equal(v.ciphertext, ct) {
        t.Errorf("Seal: expected: %x\ngot: %x", v.ciphertext, ct)
    }

    pt, err := c.Open(nil, nonce, ct, nil)
    if err != nil {
        t.Errorf("Open: %s", err)
    }

    if !bytes.Equal(v.plaintext, pt) {
        t.Errorf("Open: expected: %x\ngot: %x", v.plaintext, pt)
    }
}
