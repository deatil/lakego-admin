package xoodyak_test

import (
    "io"
    "log"
    "fmt"
    "bytes"
    "strings"

    "github.com/deatil/go-cryptobin/cipher/xoodoo/xoodyak"
)

func ExampleHashXoodyak() {
    myMsg := []byte("hello xoodoo")
    myHash := xoodyak.HashXoodyak(myMsg)
    fmt.Printf("Msg:'%s'\nHash:%x\n", myMsg, myHash)
    // Output: Msg:'hello xoodoo'
    // Hash:5c9a95363d79b2157cbdfff49dddaf1f20562dc64644f2d28211478537e6b29a
}

func ExampleHashXoodyakLen() {
    myMsg := []byte("hello xoodoo")
    myHash := xoodyak.HashXoodyakLen(myMsg, 64)
    fmt.Printf("Msg:'%s'\nHash:%x\n", myMsg, myHash)
    // Output: Msg:'hello xoodoo'
    // Hash:5c9a95363d79b2157cbdfff49dddaf1f20562dc64644f2d28211478537e6b29a5675a6d4a3fe18b985e7ae018133c118a44c5f82b3672492a30408937e5712cb
}

func ExampleNewXoodyakHash() {
    myMsg := []byte("hello xoodoo")
    msgBuf := bytes.NewBuffer(myMsg)
    xHash := xoodyak.NewXoodyakHash()
    io.Copy(xHash, msgBuf)
    myHash := xHash.Sum(nil)
    fmt.Printf("Msg:'%s'\nHash:%x\n", myMsg, myHash)
    // Output: Msg:'hello xoodoo'
    // Hash:5c9a95363d79b2157cbdfff49dddaf1f20562dc64644f2d28211478537e6b29a
}

func ExampleMACXoodyak() {
    myMsg := []byte("hello xoodoo")
    /* use a secret value here */
    myKey := []byte("abcdefghijklmnop")
    myMac := xoodyak.MACXoodyak(myKey, myMsg, 32)
    fmt.Printf("Key:%x\nMsg:'%s'\nMAC:%x\n", myKey, myMsg, myMac)
    // Output: Key:6162636465666768696a6b6c6d6e6f70
    // Msg:'hello xoodoo'
    // MAC:57abf40d9927f0ed5e65ef5b57a3ecc2da46ebb4f3fc5346202056e2b24e6121
}

func ExampleNewXoodyakMac() {
    myMsg := []byte("hello xoodoo")
    /* use a secret value here */
    myKey := []byte("abcdefghijklmnop")
    newMac := xoodyak.NewXoodyakMac(myKey)
    newMac.Write(myMsg)
    myMac := newMac.Sum(nil)
    fmt.Printf("Key:%x\nMsg:'%s'\nMAC:%x\n", myKey, myMsg, myMac)
    // Output: Key:6162636465666768696a6b6c6d6e6f70
    // Msg:'hello xoodoo'
    // MAC:57abf40d9927f0ed5e65ef5b57a3ecc2da46ebb4f3fc5346202056e2b24e6121
}

func ExampleCryptoEncryptAEAD() {
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
    var output strings.Builder
    fmt.Fprintf(&output, "Msg:'%s'\n", myMsg)
    fmt.Fprintf(&output, "Key:%x\n", myKey)
    fmt.Fprintf(&output, "Nonce:%x\n", myNonce)
    fmt.Fprintf(&output, "Metadata:%x\n", myAD)
    fmt.Fprintf(&output, "Ciphertext:%x\n", myCt)
    fmt.Fprintf(&output, "AuthTag:%x\n", myTag)
    fmt.Fprintf(&output, "DecryptOK:%t\n", valid)
    fmt.Fprintf(&output, "Plaintext:'%s'", myPt)
    fmt.Println(output.String())
    // Output: Msg:'hello xoodoo'
    // Key:0f0e0d0c0b0a09080706050403020100
    // Nonce:f0e1d2c3b4a5968778695a4b3c2d1e0f
    // Metadata:3333c2b03539e2809933392e3531e280b34e2c2037c2b03530e2809933332e3639e280b345
    // Ciphertext:fffc82f88d8bb2ba4f38b85d
    // AuthTag:6ef42d19830b3f0ecd784be7f4d10f46
    // DecryptOK:true
    // Plaintext:'hello xoodoo'
}

func ExampleNewXoodyakAEAD() {
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
    // Any sort of non-secret data
    myAD := []byte("33°59’39.51″N, 7°50’33.69″E")
    myXkAEAD, _ := xoodyak.NewXoodyakAEAD(myKey)

    myAuthCt := myXkAEAD.Seal(nil, myNonce, myMsg, myAD)
    myPt, err := myXkAEAD.Open(nil, myNonce, myAuthCt, myAD)
    // error is returned on decrypt authentication failure
    if err != nil {
        log.Fatal(err)
    }
    var output strings.Builder
    fmt.Fprintf(&output, "Msg:'%s'\n", myMsg)
    fmt.Fprintf(&output, "Key:%x\n", myKey)
    fmt.Fprintf(&output, "Nonce:%x\n", myNonce)
    fmt.Fprintf(&output, "Metadata:%x\n", myAD)
    fmt.Fprintf(&output, "Authenticated Ciphertext:%x\n", myAuthCt)
    fmt.Fprintf(&output, "Plaintext:'%s'", myPt)
    fmt.Println(output.String())
    // Output: Msg:'hello xoodoo'
    // Key:0f0e0d0c0b0a09080706050403020100
    // Nonce:f0e1d2c3b4a5968778695a4b3c2d1e0f
    // Metadata:3333c2b03539e2809933392e3531e280b34e2c2037c2b03530e2809933332e3639e280b345
    // Authenticated Ciphertext:fffc82f88d8bb2ba4f38b85d6ef42d19830b3f0ecd784be7f4d10f46
    // Plaintext:'hello xoodoo'
}

func ExampleNewEncryptStream() {
    myMsg := []byte("hello xoodoo")
    myCTBuf := bytes.NewBuffer(nil)
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
    // Any sort of non-secret data
    myAD := []byte("33°59’39.51″N, 7°50’33.69″E")
    myXkEncrypt, _ := xoodyak.NewEncryptStream(myCTBuf, myKey, myNonce, myAD)

    _, gotErr := myXkEncrypt.Write(myMsg)
    // error is returned on decrypt authentication failure
    if gotErr != nil {
        log.Fatal(gotErr)
    }

    myXkEncrypt.Close()

    var output strings.Builder
    fmt.Fprintf(&output, "Msg:'%s'\n", myMsg)
    fmt.Fprintf(&output, "Key:%x\n", myKey)
    fmt.Fprintf(&output, "Nonce:%x\n", myNonce)
    fmt.Fprintf(&output, "Metadata:%x\n", myAD)
    fmt.Fprintf(&output, "Authenticated Ciphertext:%x\n", myCTBuf.Bytes())
    fmt.Println(output.String())
    // Output: Msg:'hello xoodoo'
    // Key:0f0e0d0c0b0a09080706050403020100
    // Nonce:f0e1d2c3b4a5968778695a4b3c2d1e0f
    // Metadata:3333c2b03539e2809933392e3531e280b34e2c2037c2b03530e2809933332e3639e280b345
    // Authenticated Ciphertext:fffc82f88d8bb2ba4f38b85d6ef42d19830b3f0ecd784be7f4d10f46
}

func ExampleNewDecryptStream() {
    myCt := []byte{
        0xff, 0xfc, 0x82, 0xf8,
        0x8d, 0x8b, 0xb2, 0xba,
        0x4f, 0x38, 0xb8, 0x5d,
        0x6e, 0xf4, 0x2d, 0x19,
        0x83, 0x0b, 0x3f, 0x0e,
        0xcd, 0x78, 0x4b, 0xe7,
        0xf4, 0xd1, 0x0f, 0x46}
    myCtBuf := bytes.NewBuffer(myCt)
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
    // Any sort of non-secret data
    myAD := []byte("33°59’39.51″N, 7°50’33.69″E")
    myXkDecrypt, _ := xoodyak.NewDecryptStream(myCtBuf, myKey, myNonce, myAD)

    myPt := make([]byte, 12)
    _, gotErr := myXkDecrypt.Read(myPt)
    // error is returned on decrypt authentication failure
    if gotErr != nil {
        log.Fatal(gotErr)
    }

    var output strings.Builder
    fmt.Fprintf(&output, "Input Ciphertext:%x\n", myCt)
    fmt.Fprintf(&output, "Key:%x\n", myKey)
    fmt.Fprintf(&output, "Nonce:%x\n", myNonce)
    fmt.Fprintf(&output, "Metadata:%x\n", myAD)
    fmt.Fprintf(&output, "Output Message:'%s'\n", string(myPt))
    fmt.Println(output.String())
    // Output: Input Ciphertext:fffc82f88d8bb2ba4f38b85d6ef42d19830b3f0ecd784be7f4d10f46
    // Key:0f0e0d0c0b0a09080706050403020100
    // Nonce:f0e1d2c3b4a5968778695a4b3c2d1e0f
    // Metadata:3333c2b03539e2809933392e3531e280b34e2c2037c2b03530e2809933332e3639e280b345
    // Output Message:'hello xoodoo'
}
