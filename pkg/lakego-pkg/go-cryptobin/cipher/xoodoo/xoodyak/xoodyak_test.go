package xoodyak_test

import (
    "fmt"
    "testing"

    "github.com/deatil/go-cryptobin/cipher/xoodoo/xoodyak"
)

func Test_HashXoodyak(t *testing.T) {
    m := []byte("hello xoodoo")
    hash := xoodyak.HashXoodyak(m)

    check := "5c9a95363d79b2157cbdfff49dddaf1f20562dc64644f2d28211478537e6b29a"
    if fmt.Sprintf("%x", hash) != check {
        t.Errorf("fail, got %x, want %s", hash, check)
    }
}

func Test_CryptoEncryptAEAD(t *testing.T) {
    myMsg := []byte("hello xoodoo")
    // Normally, this is randomly generated and kept secret
    myKey := []byte{
        0x0F, 0x0E, 0x0D, 0x0C,
        0x0B, 0x0A, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04,
        0x03, 0x02, 0x01, 0x00,
    }
    // Normally, this is randomly generated and never repeated per key
    myNonce := []byte{
        0xF0, 0xE1, 0xD2, 0xC3,
        0xB4, 0xA5, 0x96, 0x87,
        0x78, 0x69, 0x5A, 0x4B,
        0x3C, 0x2D, 0x1E, 0x0F,
    }
    // Any sort of non-secret information about the plaintext or context of encryption
    myAD := []byte("33°59’39.51″N, 7°50’33.69″E")
    myCt, myTag, _ := xoodyak.CryptoEncryptAEAD(myMsg, myKey, myNonce, myAD)
    myPt, valid, _ := xoodyak.CryptoDecryptAEAD(myCt, myKey, myNonce, myAD, myTag)

    authTag := "6ef42d19830b3f0ecd784be7f4d10f46"
    if fmt.Sprintf("%x", myTag) != authTag {
        t.Errorf("authTag fail, got %x, want %s", myTag, authTag)
    }

    ciphertext := "fffc82f88d8bb2ba4f38b85d"
    if fmt.Sprintf("%x", myCt) != ciphertext {
        t.Errorf("ciphertext fail, got %x, want %s", myCt, ciphertext)
    }

    if !valid {
        t.Error("DecryptOK fail")
    }

    if string(myPt) != string(myMsg) {
        t.Errorf("Plaintext fail, got %s, want %s", string(myPt), string(myMsg))
    }
}
